"""Code shared between all platforms."""
import asyncio
import logging
from datetime import timedelta
import platform
import subprocess
from anyio import sleep

from sqlalchemy import true
from homeassistant.config_entries import ConfigEntry

from homeassistant.const import (
    CONF_DEVICE_ID,
    CONF_ENTITIES,
    CONF_FRIENDLY_NAME,
    CONF_HOST,
    CONF_ID,
    CONF_PLATFORM,
    CONF_SCAN_INTERVAL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.dispatcher import (
    async_dispatcher_connect,
    async_dispatcher_send,
)
from homeassistant.helpers.restore_state import RestoreEntity

from . import pytuya
from .const import (
    CONF_LOCAL_KEY,
    CONF_PRODUCT_KEY,
    CONF_PROTOCOL_VERSION,
    CONF_IS_GATEWAY,
    CONF_PARENT_GATEWAY,
    DOMAIN,
    GW_REQ_ADD,
    GW_REQ_REMOVE,
    GW_REQ_STATUS,
    GW_REQ_SET_DP,
    GW_REQ_SET_DPS,
    GW_EVT_REQ_ACK,
    GW_EVT_STATUS_UPDATED,
    GW_EVT_CONNECTED,
    GW_EVT_DISCONNECTED,
    SUB_DEVICE_RECONNECT_INTERVAL,
    SUB_DEVICE_DISPATCH_RETRY_MAX,
    SUB_DEVICE_DISPATCH_RETRY_INTERVAL,
    TUYA_DEVICE,
)

_LOGGER = logging.getLogger(__name__)


def prepare_setup_entities(hass, config_entry, platform):
    """Prepare ro setup entities for a platform."""
    entities_to_setup = [
        entity
        for entity in config_entry.data[CONF_ENTITIES]
        if entity[CONF_PLATFORM] == platform
    ]
    if not entities_to_setup:
        return None, None

    tuyainterface = hass.data[DOMAIN][config_entry.entry_id][TUYA_DEVICE]

    return tuyainterface, entities_to_setup


async def async_setup_entry(
    domain: str,
    entity_class: type,
    flow_schema,
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    """Set up a Tuya platform based on a config entry.

    This is a generic method and each platform should lock domain and
    entity_class with functools.partial.
    """
    tuyainterface, entities_to_setup = prepare_setup_entities(
        hass, config_entry, domain
    )

    if not entities_to_setup:
        return
    dps_config_fields = list(get_dps_for_platform(flow_schema))

    for device_config in entities_to_setup:
        # Add DPS used by this platform to the request list
        for dp_conf in dps_config_fields:
            if dp_conf in device_config:
                tuyainterface.dps_to_request[device_config[dp_conf]] = None
        async_add_entities(
            [
                entity_class(
                    tuyainterface,
                    config_entry,
                    device_config[CONF_ID],
                )
            ],
            True,
        )


def get_dps_for_platform(flow_schema):
    """Return config keys for all platform keys that depends on a datapoint."""
    for key, value in flow_schema(None).items():
        if hasattr(value, "container") and value.container is None:
            yield key.schema


def get_entity_config(config_entry, dp_id):
    """Return entity config for a given DPS id."""
    for entity in config_entry.data[CONF_ENTITIES]:
        if entity[CONF_ID] == dp_id:
            return entity
    raise Exception(f"missing entity config for id {dp_id}")


@callback
def async_config_entry_by_device_id(hass, device_id):
    """Look up config entry by device id."""
    current_entries = hass.config_entries.async_entries(DOMAIN)
    for entry in current_entries:
        if entry.data[CONF_DEVICE_ID] == device_id:
            return entry
    return None


class TuyaDevice(pytuya.TuyaListener, pytuya.ContextualLogger):
    """Cache wrapper for pytuya.TuyaInterface."""

    def __init__(self, hass, config_entry):
        """Initialize the cache."""
        super().__init__()
        self._hass = hass
        self._config_entry = config_entry
        self._interface = None
        self._status = {}
        self.dps_to_request = {}
        self._is_closing = False
        self._connect_task = None
        self._disconnect_task = None
        self._unsub_interval = None
        self.set_logger(_LOGGER, config_entry[CONF_DEVICE_ID])

        # This has to be done in case the device type is type_0d
        for entity in config_entry[CONF_ENTITIES]:
            self.dps_to_request[entity[CONF_ID]] = None

    @property
    def connected(self):
        """Return if connected to device."""
        return self._interface is not None

    def async_connect(self):
        """Connect to device if not already connected."""
        if not self._is_closing and self._connect_task is None and not self._interface:
            self._connect_task = asyncio.create_task(self._make_connection())

    async def _make_connection(self):
        """Subscribe localtuya entity events."""
        self.debug("Connecting to %s", self._config_entry[CONF_HOST])
        try:
            self._interface = await pytuya.connect(
                self._config_entry[CONF_HOST],
                self._config_entry[CONF_DEVICE_ID],
                self._config_entry[CONF_LOCAL_KEY],
                float(self._config_entry[CONF_PROTOCOL_VERSION]),
                self,
            )

            self._interface.add_dps_to_request(self.dps_to_request)

            self.debug("Retrieving initial state")
            status = await self._interface.status()
            if status is None:
                raise Exception("Failed to retrieve status")

            self.status_updated(status)

            if self._disconnect_task is not None:
                self._disconnect_task()

            def _new_entity_handler(entity_id):
                self.debug(
                    "New entity %s was added to %s",
                    entity_id,
                    self._config_entry[CONF_HOST],
                )
                self._dispatch_status()

            signal = f"localtuya_entity_{self._config_entry[CONF_DEVICE_ID]}"
            self._disconnect_task = async_dispatcher_connect(
                self._hass, signal, _new_entity_handler
            )

            if (
                CONF_SCAN_INTERVAL in self._config_entry
                and self._config_entry[CONF_SCAN_INTERVAL] > 0
            ):
                self._unsub_interval = async_track_time_interval(
                    self._hass,
                    self._async_refresh,
                    timedelta(seconds=self._config_entry[CONF_SCAN_INTERVAL]),
                )
        except Exception:  # pylint: disable=broad-except
            self.exception(f"Connect to {self._config_entry[CONF_HOST]} failed")
            if self._interface is not None:
                await self._interface.close()
                self._interface = None
        self._connect_task = None

        if self._interface is not None:
            try:
                self.debug("Retrieving initial state")
                status = await self._interface.status()
                if status is None or not status:
                    raise Exception("Failed to retrieve status")

                self._interface.start_heartbeat()
                self.status_updated(status)

            except Exception:  # pylint: disable=broad-except
                try:
                    if self._interface is not None:
                        self.debug("Initial state update failed, trying refresh command")
                        await self._interface.refresh()

                        self.debug("Refresh completed, retrying initial state")
                        status = await self._interface.status()
                        if status is None or not status:
                            raise Exception("Failed to retrieve status")

                        self._interface.start_heartbeat()
                        self.status_updated(status)
                    else:
                        raise Exception("Interface went away")
                except Exception:  # pylint: disable=broad-except
                    self.exception(f"Refresh/initial status update of {self._config_entry[CONF_HOST]} failed")
                    if self._interface is not None:
                        await self._interface.close()
                        self._interface = None

    async def _async_refresh(self, _now):
        if self._interface is not None:
            await self._interface.update_dps()

    async def close(self):
        """Close connection and stop re-connect loop."""
        self._is_closing = True
        if self._connect_task is not None:
            self._connect_task.cancel()
            await self._connect_task
        if self._interface is not None:
            await self._interface.close()
        if self._disconnect_task is not None:
            self._disconnect_task()

    async def set_dp(self, state, dp_index):
        """Change value of a DP of the Tuya device."""
        if self._interface is not None:
            try:
                await self._interface.set_dp(state, dp_index)
            except Exception:  # pylint: disable=broad-except
                self.exception("Failed to set DP %d to %d", dp_index, state)
        else:
            self.error(
                "Not connected to device %s", self._config_entry[CONF_FRIENDLY_NAME]
            )

    async def set_dps(self, states):
        """Change value of a DPs of the Tuya device."""
        if self._interface is not None:
            try:
                await self._interface.set_dps(states)
            except Exception:  # pylint: disable=broad-except
                self.exception("Failed to set DPs %r", states)
        else:
            self.error(
                "Not connected to device %s", self._config_entry[CONF_FRIENDLY_NAME]
            )

    @callback
    def status_updated(self, status):
        """Device updated status."""
        if status:
            self._status.update(status)

            signal = f"localtuya_{self._config_entry[CONF_DEVICE_ID]}"
            async_dispatcher_send(self._hass, signal, self._status)
        else:
            self.debug("Received empty status update (likely for refresh)")
        self._dispatch_status()

    def _dispatch_status(self):
        signal = f"localtuya_{self._config_entry[CONF_DEVICE_ID]}"
        async_dispatcher_send(self._hass, signal, self._status)

    @callback
    def disconnected(self):
        """Device disconnected."""
        signal = f"localtuya_{self._config_entry[CONF_DEVICE_ID]}"
        async_dispatcher_send(self._hass, signal, None)
        if self._unsub_interval is not None:
            self._unsub_interval()
            self._unsub_interval = None
        self._interface = None
        self.debug("Disconnected - waiting for discovery broadcast")


class TuyaGatewayDevice(pytuya.TuyaListener, pytuya.ContextualLogger):
    """Gateway wrapper for pytuya.TuyaInterface."""

    def __init__(self, hass, config_entry):
        """Initialize the cache."""
        super().__init__()
        self._hass = hass
        self._config_entry = config_entry
        self._interface = None
        self._is_closing = False
        self._connect_task = asyncio.create_task(self._make_connection())
        self._disconnect_task = None
        self._retry_sub_conn_interval = None
        self._sub_devices = {}
        self.set_logger(_LOGGER, config_entry[CONF_DEVICE_ID])

        # Safety check
        if not config_entry.get(CONF_IS_GATEWAY):
            raise Exception(
                "Device {0} is not a gateway but using TuyaGatewayDevice!",
                config_entry[CONF_DEVICE_ID],
            )

    @property
    def connected(self):
        """Return if connected to device."""
        return self._interface is not None

    def async_connect(self):
        """Connect to device if not already connected."""
        if not self._is_closing and self._connect_task is None and not self._interface:
            self._connect_task = asyncio.create_task(self._make_connection())

    async def _make_connection(self):
        """Subscribe localtuya entity events."""
        self.debug("Connecting to gateway %s", self._config_entry[CONF_HOST])
        try:
            self._interface = await pytuya.connect(
                self._config_entry[CONF_HOST],
                self._config_entry[CONF_DEVICE_ID],
                self._config_entry[CONF_LOCAL_KEY],
                float(self._config_entry[CONF_PROTOCOL_VERSION]),
                self,
                is_gateway=True,
            )

            if self._disconnect_task is not None:
                self._disconnect_task()

            signal = f"localtuya_gateway_{self._config_entry[CONF_DEVICE_ID]}"
            self._disconnect_task = async_dispatcher_connect(
                self._hass, signal, self._handle_sub_device_request
            )

            # Re-add and get status of previously added sub-devices
            for cid in self._sub_devices:
                self._add_sub_device_interface(cid, self._sub_devices[cid]["dps"])
                self._dispatch_event(GW_EVT_CONNECTED, None, cid)

                # Initial status update
                await self._get_sub_device_status(cid, False)

            self._retry_sub_conn_interval = async_track_time_interval(
                self._hass,
                self._retry_sub_device_connection,
                timedelta(seconds=SUB_DEVICE_RECONNECT_INTERVAL),
            )

        except Exception:  # pylint: disable=broad-except
            self.exception(f"Connect to gateway {self._config_entry[CONF_HOST]} failed")
            if self._interface is not None:
                await self._interface.close()
                self._interface = None
        self._connect_task = None

    async def _handle_sub_device_request(self, data):
        """Handle requests from sub-devices"""
        request = data["request"]
        cid = data["cid"]
        content = data["content"]

        self.debug("Received request %s from %s with content %s", request, cid, content)
        self._dispatch_event(GW_EVT_REQ_ACK, None, cid)

        if request == GW_REQ_ADD:
            if cid in self._sub_devices:
                self.warning("Duplicate sub-device addition for %s", cid)
            else:
                self._sub_devices[cid] = {"dps": content["dps"], "retry_status": False}
                self._add_sub_device_interface(cid, content["dps"])
                self._dispatch_event(GW_EVT_CONNECTED, None, cid)
                # Initial status update
                await self._get_sub_device_status(cid, False)
        elif request == GW_REQ_REMOVE:
            if cid not in self._sub_devices:
                self.warning("Invalid sub-device removal request for %s", cid)
            else:
                del self._sub_devices[cid]
                self._interface.remove_sub_device(cid)
                self._dispatch_event(GW_EVT_DISCONNECTED, None, cid)
        elif request == GW_REQ_STATUS:
            status = await self._interface.status(cid)
            self.status_updated(status)
        elif request == GW_REQ_SET_DP:
            await self._interface.set_dp(content["value"], content["dp_index"], cid)
        elif request == GW_REQ_SET_DPS:
            await self._interface.set_dps(content["dps"], cid)
        else:
            self.debug("Invalid request %s from %s", request, cid)

    def _add_sub_device_interface(self, cid, dps):
        self._interface.add_sub_device(cid)
        self._interface.add_dps_to_request(dps, cid)

    async def _get_sub_device_status(self, cid, is_retry):
        status = await self._interface.status(cid)
        if status:
            self.status_updated(status)
            self._sub_devices[cid]["retry_status"] = False
            if is_retry:
                self._dispatch_event(GW_EVT_CONNECTED, None, cid)
        else:
            self._sub_devices[cid]["retry_status"] = True
            if not is_retry:
                self._dispatch_event(GW_EVT_DISCONNECTED, None, cid)

    def _dispatch_event(self, event, event_data, cid):
        self.debug(
            "Dispatching event %s to sub-device %s with data %s", event, cid, event_data
        )

        async_dispatcher_send(
            self._hass,
            f"localtuya_subdevice_{cid}",
            {"event": event, "event_data": event_data},
        )

    async def _retry_sub_device_connection(self, _now):
        for cid in self._sub_devices:
            if self._sub_devices[cid]["retry_status"]:
                await self._get_sub_device_status(cid, True)

    async def close(self):
        """Close connection and stop re-connect loop."""
        self._is_closing = True
        if self._connect_task is not None:
            self._connect_task.cancel()
            await self._connect_task
        if self._interface is not None:
            await self._interface.close()
        if self._disconnect_task is not None:
            self._disconnect_task()

    @callback
    def status_updated(self, status):
        """Device updated status."""
        cid = status["last_updated_cid"]
        if cid == "":  # Not a status update we are interested in
            return

        self._dispatch_event(GW_EVT_STATUS_UPDATED, status[cid], cid)

    @callback
    def disconnected(self):
        """Device disconnected."""
        if self._retry_sub_conn_interval is not None:
            self._retry_sub_conn_interval()
            self._retry_sub_conn_interval = None

        for cid in self._sub_devices:
            self._dispatch_event(GW_EVT_DISCONNECTED, None, cid)

        self._interface = None
        self.debug("Disconnected - waiting for discovery broadcast")


class TuyaSubDevice(pytuya.TuyaListener, pytuya.ContextualLogger):
    """Cache wrapper for a sub-device under a gateway."""

    def __init__(self, hass, config_entry):
        """Initialize the cache."""
        super().__init__()
        self._hass = hass
        self._config_entry = config_entry
        self._parent_gateway = config_entry.get(CONF_PARENT_GATEWAY)
        self._status = {}
        self.dps_to_request = {}
        self._device_disconnect_task = None
        self._entity_disconnect_task = None
        self._is_closing = False
        self._is_connected = False
        self._is_added = False
        self._pending_request = {"request": None, "content": None, "retry_count": 0}
        self.set_logger(_LOGGER, config_entry[CONF_DEVICE_ID])

        # Safety check
        if not config_entry.get(CONF_PARENT_GATEWAY):
            raise Exception(
                "Device {0} is not a sub-device but using TuyaSubDevice!",
                config_entry[CONF_DEVICE_ID],
            )

        # Populate dps list from entities
        for entity in config_entry[CONF_ENTITIES]:
            self.dps_to_request[entity[CONF_ID]] = None

    @property
    def connected(self):
        """Return if connected to device."""
        return self._is_connected

    def async_connect(self):
        """Add device if not added."""
        if not self._is_added and not self._is_closing:
            self.debug(
                "Connecting to sub-device %s via %s",
                self._config_entry[CONF_DEVICE_ID],
                self._parent_gateway,
            )

            signal = f"localtuya_subdevice_{self._config_entry[CONF_DEVICE_ID]}"
            self._device_disconnect_task = async_dispatcher_connect(
                self._hass, signal, self._handle_gateway_event
            )

            def _new_entity_handler(entity_id):
                self.debug(
                    "New entity %s was added to %s",
                    entity_id,
                    self._config_entry[CONF_DEVICE_ID],
                )
                self._dispatch_status()

            signal = f"localtuya_entity_{self._config_entry[CONF_DEVICE_ID]}"
            self._entity_disconnect_task = async_dispatcher_connect(
                self._hass, signal, _new_entity_handler
            )

            self._async_dispatch_gateway_request(
                GW_REQ_ADD, {"dps": self.dps_to_request}
            )

            self._is_added = True

    def _handle_gateway_event(self, data):
        """Handle events from gateway"""
        event = data["event"]
        event_data = data["event_data"]

        self.debug("Received event %s from gateway with data %s", event, event_data)

        if event == GW_EVT_REQ_ACK:
            if self._pending_request["request"]:
                self.debug("Request %s acknowledged", self._pending_request["request"])
                self._pending_request["request"] = None
            else:
                self.debug("Gateway acknowledged request but none pending")
        elif event == GW_EVT_STATUS_UPDATED:
            self.status_updated(event_data)
        elif event == GW_EVT_CONNECTED:
            self._is_connected = True
        elif event == GW_EVT_DISCONNECTED:
            self.disconnected()
        else:
            self.debug("Invalid event %s from gateway", event)

    def _async_dispatch_gateway_request(self, request, content):
        self.debug(
            "Dispatching request %s to gateway with content %s", request, content
        )
        asyncio.create_task(self._gateway_request_task(request, content))

    async def _gateway_request_task(self, request, content):
        if self._pending_request["request"]:
            self.debug(
                "Unable to dispatch request %s due to pending request %s",
                request,
                self._pending_request["request"],
            )

            return

        self._pending_request["request"] = request
        self._pending_request["content"] = content
        self._pending_request["retry_count"] = 0

        while True:
            if not self._pending_request["request"]:
                return

            if self._pending_request["retry_count"] >= SUB_DEVICE_DISPATCH_RETRY_MAX:
                self.debug(
                    "Request %s exceeded maximum retries",
                    self._pending_request["request"],
                )
                self._pending_request["request"] = None
                return

            async_dispatcher_send(
                self._hass,
                f"localtuya_gateway_{self._parent_gateway}",
                {
                    "request": self._pending_request["request"],
                    "cid": self._config_entry[CONF_DEVICE_ID],
                    "content": self._pending_request["content"],
                },
            )

            self._pending_request["retry_count"] += 1
            await asyncio.sleep(SUB_DEVICE_DISPATCH_RETRY_INTERVAL)

    async def set_dp(self, state, dp_index):
        """Change value of a DP of the Tuya device."""
        if self._is_connected:
            self._async_dispatch_gateway_request(
                GW_REQ_SET_DP,
                {
                    "value": state,
                    "dp_index": dp_index,
                },
            )
        else:
            self.error(
                "Not connected to device %s", self._config_entry[CONF_FRIENDLY_NAME]
            )

    async def set_dps(self, states):
        """Change value of DPs of the Tuya device."""
        if self._is_connected:
            self._async_dispatch_gateway_request(
                GW_REQ_SET_DPS,
                {
                    "dps": states,
                },
            )
        else:
            self.error(
                "Not connected to device %s", self._config_entry[CONF_FRIENDLY_NAME]
            )

    async def close(self):
        """Close connection and stop re-connect loop."""
        self._is_closing = True
        self._async_dispatch_gateway_request(GW_REQ_REMOVE, None)
        self._is_added = False
        if self._device_disconnect_task is not None:
            self._device_disconnect_task()
        if self._entity_disconnect_task is not None:
            self._entity_disconnect_task()

    @callback
    def status_updated(self, status):
        """Device updated status."""
        self._status.update(status)
        self._dispatch_status()

    def _dispatch_status(self):
        signal = f"localtuya_{self._config_entry[CONF_DEVICE_ID]}"
        async_dispatcher_send(self._hass, signal, self._status)

    @callback
    def disconnected(self):
        """Device disconnected."""
        self._is_connected = False
        signal = f"localtuya_{self._config_entry[CONF_DEVICE_ID]}"
        async_dispatcher_send(self._hass, signal, None)

        self.debug("Disconnected")


class LocalTuyaEntity(RestoreEntity, pytuya.ContextualLogger):
    """Representation of a Tuya entity."""

    def __init__(self, device, config_entry, dp_id, logger, **kwargs):
        """Initialize the Tuya entity."""
        super().__init__()
        self._device = device
        self._config_entry = config_entry
        self._config = get_entity_config(config_entry, dp_id)
        self._dp_id = dp_id
        self._status = {}
        self.set_logger(logger, self._config_entry.data[CONF_DEVICE_ID])

    async def async_added_to_hass(self):
        """Subscribe localtuya events."""
        await super().async_added_to_hass()

        self.debug("Adding %s with configuration: %s", self.entity_id, self._config)

        state = await self.async_get_last_state()
        if state:
            self.status_restored(state)

        def _update_handler(status):
            """Update entity state when status was updated."""
            if status is None:
                status = {}
            if self._status != status:
                self._status = status.copy()
                if status:
                    self.status_updated()
                self.schedule_update_ha_state()

        signal = f"localtuya_{self._config_entry.data[CONF_DEVICE_ID]}"

        self.async_on_remove(
            async_dispatcher_connect(self.hass, signal, _update_handler)
        )

        signal = f"localtuya_entity_{self._config_entry.data[CONF_DEVICE_ID]}"
        async_dispatcher_send(self.hass, signal, self.entity_id)

    @property
    def device_info(self):
        """Return device information for the device registry."""
        return {
            "identifiers": {
                # Serial numbers are unique identifiers within a specific domain
                (DOMAIN, f"local_{self._config_entry.data[CONF_DEVICE_ID]}")
            },
            "name": self._config_entry.data[CONF_FRIENDLY_NAME],
            "manufacturer": "Unknown",
            "model": self._config_entry.data.get(CONF_PRODUCT_KEY, "Tuya generic"),
            "sw_version": self._config_entry.data[CONF_PROTOCOL_VERSION],
        }

    @property
    def name(self):
        """Get name of Tuya entity."""
        return self._config[CONF_FRIENDLY_NAME]

    @property
    def should_poll(self):
        """Return if platform should poll for updates."""
        return False

    @property
    def unique_id(self):
        """Return unique device identifier."""
        return f"local_{self._config_entry.data[CONF_DEVICE_ID]}_{self._dp_id}"

    def has_config(self, attr):
        """Return if a config parameter has a valid value."""
        value = self._config.get(attr, "-1")
        return value is not None and value != "-1"

    @property
    def available(self):
        """Return if device is available or not."""
        return str(self._dp_id) in self._status

    def dps(self, dp_index):
        """Return cached value for DPS index."""
        value = self._status.get(str(dp_index))
        if value is None:
            self.warning(
                "Entity %s is requesting unknown DPS index %s",
                self.entity_id,
                dp_index,
            )

        return value

    def dps_conf(self, conf_item):
        """Return value of datapoint for user specified config item.

        This method looks up which DP a certain config item uses based on
        user configuration and returns its value.
        """
        dp_index = self._config.get(conf_item)
        if dp_index is None:
            self.warning(
                "Entity %s is requesting unset index for option %s",
                self.entity_id,
                conf_item,
            )
        return self.dps(dp_index)

    def status_updated(self):
        """Device status was updated.

        Override in subclasses and update entity specific state.
        """

    def status_restored(self, stored_state):
        """Device status was restored.

        Override in subclasses and update entity specific state.
        """
