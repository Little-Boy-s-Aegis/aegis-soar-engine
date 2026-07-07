import logging
import os
import json
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.mqtt")

# Graceful fallback if paho-mqtt is not installed
try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False
    logger.warning(
        "[MQTT] paho-mqtt library not installed. "
        "Install with: pip install paho-mqtt. Running in fallback/simulation mode."
    )


class MqttConnector:
    """MQTT Client Connector for publishing IoT/OT security events to an MQTT broker."""

    def __init__(self):
        self.broker = os.getenv("MQTT_BROKER", "mock-mqtt-broker")
        self.port = int(os.getenv("MQTT_PORT", "1883"))
        self.topic_prefix = os.getenv("MQTT_TOPIC_PREFIX", "soar-engine/security")
        self.username = os.getenv("MQTT_USERNAME", "")
        self.password = secrets.get_secret("MQTT_PASSWORD", "")

    def _is_simulation(self) -> bool:
        """Returns True if running in simulation/mock mode."""
        return self.broker == "mock-mqtt-broker"

    def _get_topic(self, subtopic: str) -> str:
        """Builds the full MQTT topic from prefix and subtopic."""
        return f"{self.topic_prefix}/{subtopic}"

    def _publish(self, topic: str, payload: dict) -> tuple[bool, str]:
        """
        Internal helper to connect to the MQTT broker and publish a JSON message.
        Returns (success, message).
        """
        message_json = json.dumps(payload)

        if self._is_simulation():
            logger.info(
                f"[MQTT-SIMULATION] Published to '{topic}': {message_json[:150]}..."
            )
            return True, f"[SIMULATION] MQTT message published to '{topic}'."

        if not PAHO_AVAILABLE:
            logger.error("[MQTT] Cannot publish: paho-mqtt library is not installed.")
            return False, "MQTT publish failed: paho-mqtt library is not installed."

        try:
            client = mqtt.Client(client_id="soar-engine-publisher", protocol=mqtt.MQTTv311)

            # Set credentials if configured
            if self.username:
                client.username_pw_set(self.username, self.password)

            client.connect(self.broker, self.port, keepalive=30)

            result = client.publish(topic, message_json, qos=1)
            result.wait_for_publish(timeout=10)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                logger.info(f"[MQTT] Message published to '{topic}' (mid: {result.mid}).")
                client.disconnect()
                return True, f"MQTT message published to '{topic}' (mid: {result.mid})."
            else:
                logger.error(f"[MQTT] Publish failed with rc={result.rc}.")
                client.disconnect()
                return False, f"MQTT publish failed with return code: {result.rc}"

        except Exception as e:
            logger.error(f"[MQTT ERROR] Failed to publish message: {e}")
            return False, f"MQTT connection error: {str(e)}"

    def publish_event(self, event: dict, subtopic: str = "alerts") -> tuple[bool, str]:
        """
        Publishes a JSON security event to the MQTT broker.
        The full topic is: {MQTT_TOPIC_PREFIX}/{subtopic}
        Returns (success, message).
        """
        topic = self._get_topic(subtopic)
        logger.info(f"[MQTT] Publishing event to '{topic}'")
        return self._publish(topic, event)

    def publish_recovery(self, event: dict) -> tuple[bool, str]:
        """
        Publishes a recovery event to the MQTT broker under the 'recovery' subtopic.
        Returns (success, message).
        """
        topic = self._get_topic("recovery")
        logger.info(f"[MQTT] Publishing recovery event to '{topic}'")
        return self._publish(topic, event)
