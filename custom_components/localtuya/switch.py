"""Platform to locally control Tuya-based switch devices."""

from functools import partial
import logging

import voluptuous as vol

from homeassistant.components.switch import DOMAIN as SWITCH_DOMAIN, SwitchEntity

from .common import LocalTuyaEntity, async_setup_entry
from .const import (
    ATTR_CURRENT,
    ATTR_CURRENT_CONSUMPTION,
    ATTR_STATE,
    ATTR_VOLTAGE,
    CONF_CURRENT,
    CONF_CURRENT_CONSUMPTION,
    CONF_DEFAULT_VALUE,
    CONF_RESTORE_ON_RECONNECT,
    CONF_VOLTAGE,
)

_LOGGER = logging.getLogger(__name__)


def flow_schema(dps):
    """Return schema used in config flow."""
    return {
        vol.Optional(CONF_CURRENT): vol.In(dps),
        vol.Optional(CONF_CURRENT_CONSUMPTION): vol.In(dps),
        vol.Optional(CONF_VOLTAGE): vol.In(dps),
        vol.Required(CONF_RESTORE_ON_RECONNECT, default=True): bool,
        vol.Optional(CONF_DEFAULT_VALUE): str,
    }


class LocaltuyaSwitch(LocalTuyaEntity, SwitchEntity):
    """Representation of a Tuya switch."""

    def __init__(
        self,
        device,
        config_entry,
        switchid,
        **kwargs,
    ):
        """Initialize the Tuya switch."""
        super().__init__(device, config_entry, switchid, _LOGGER, **kwargs)
        self._state = None
        _LOGGER.debug("Initialized switch [%s]", self.name)

    @property
    def is_on(self):
        """Check if Tuya switch is on."""
        return self._state

    @property
    def extra_state_attributes(self):
        """Return device state attributes."""
        attrs = {}
        if self.has_config(CONF_CURRENT):
            current = self.dps(self._config[CONF_CURRENT])
            if current is not None:
                attrs[ATTR_CURRENT] = current
        if self.has_config(CONF_CURRENT_CONSUMPTION):
            consumption = self.dps(self._config[CONF_CURRENT_CONSUMPTION])
            if consumption is not None:
                attrs[ATTR_CURRENT_CONSUMPTION] = consumption / 10
        if self.has_config(CONF_VOLTAGE):
            voltage = self.dps(self._config[CONF_VOLTAGE])
            if voltage is not None:
                attrs[ATTR_VOLTAGE] = voltage / 10
        # Store the state
        if self._state is not None:
            attrs[ATTR_STATE] = self._state
        elif self._last_state is not None:
            attrs[ATTR_STATE] = self._last_state
        return attrs

    async def async_turn_on(self, **kwargs):
        """Turn Tuya switch on."""
        await self._device.set_dp(True, self._dp_id)

    async def async_turn_off(self, **kwargs):
        """Turn Tuya switch off."""
        await self._device.set_dp(False, self._dp_id)

    def status_updated(self):
        """Device status was updated."""
        state = self.dps(self._dp_id)
        if state is not None:
            self._state = state

    # Default value is the "OFF" state
    def entity_default_value(self):
        """Return False as the default value for this entity type."""
        return False


async_setup_entry = partial(
    async_setup_entry, SWITCH_DOMAIN, LocaltuyaSwitch, flow_schema
)
