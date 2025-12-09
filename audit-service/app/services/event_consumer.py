"""
Event consumer using PostgreSQL LISTEN/NOTIFY.

This module implements async event consumption from PostgreSQL
notifications, enabling real-time processing of audit events
for purposes like:
- Search indexing (Meilisearch)
- Alerting and notifications
- Webhooks
- Analytics aggregation
"""

import asyncio
import json
import logging
from typing import Callable, Dict, Any, Optional, List

import asyncpg

from app.config import settings

logger = logging.getLogger(__name__)


class EventConsumer:
    """
    PostgreSQL LISTEN/NOTIFY event consumer.
    
    Listens for new audit events and dispatches them to registered handlers.
    This replaces the need for Kafka/RabbitMQ for async processing.
    """
    
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or settings.database_url
        self._connection: Optional[asyncpg.Connection] = None
        self._handlers: List[Callable] = []
        self._running = False
    
    def add_handler(self, handler: Callable):
        """
        Register an event handler.
        
        Args:
            handler: Async function that takes event dict as argument
        """
        self._handlers.append(handler)
        logger.info(f"Registered event handler: {handler.__name__}")
    
    async def connect(self):
        """Establish database connection for listening."""
        dsn = self.database_url
        if dsn.startswith("postgresql+asyncpg://"):
            dsn = dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
        
        self._connection = await asyncpg.connect(dsn)
        logger.info("Event consumer connected to PostgreSQL")
    
    async def disconnect(self):
        """Close the database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            logger.info("Event consumer disconnected")
    
    async def _notification_handler(
        self,
        connection: asyncpg.Connection,
        pid: int,
        channel: str,
        payload: str
    ):
        """
        Handle incoming notifications.
        
        Args:
            connection: The database connection
            pid: Process ID of the notifying backend
            channel: Notification channel name
            payload: Notification payload (JSON string)
        """
        try:
            event = json.loads(payload)
            logger.debug(f"Received event: {event}")
            
            # Dispatch to all handlers
            for handler in self._handlers:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Handler {handler.__name__} failed: {e}")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse notification payload: {e}")
    
    async def start(self, channel: str = "audit_events"):
        """
        Start listening for events.
        
        Args:
            channel: PostgreSQL NOTIFY channel to listen on
        """
        if not self._connection:
            await self.connect()
        
        await self._connection.add_listener(channel, self._notification_handler)
        self._running = True
        
        logger.info(f"Listening on channel: {channel}")
        
        # Keep alive
        while self._running:
            await asyncio.sleep(1)
    
    async def stop(self):
        """Stop listening and disconnect."""
        self._running = False
        await self.disconnect()


# ============================================================================
# Built-in Handlers
# ============================================================================

async def log_event_handler(event: Dict[str, Any]):
    """Simple handler that logs events."""
    logger.info(f"New event: service={event.get('service_id')}, type={event.get('event_type')}")


async def meilisearch_indexer(event: Dict[str, Any]):
    """
    Index events to Meilisearch for full-text search.
    
    Requires Meilisearch to be configured in settings.
    """
    if not settings.meilisearch_url:
        return
    
    try:
        import meilisearch
        
        client = meilisearch.Client(
            settings.meilisearch_url,
            settings.meilisearch_api_key
        )
        
        index = client.index('audit_events')
        
        # Fetch full event from database
        # (notification only contains basic info)
        # In a real implementation, you'd fetch the full event
        
        await index.add_documents([{
            'id': event.get('id'),
            'service_id': event.get('service_id'),
            'event_type': event.get('event_type'),
            # Add more fields as needed
        }])
        
        logger.debug(f"Indexed event {event.get('id')} to Meilisearch")
        
    except ImportError:
        logger.warning("Meilisearch client not installed")
    except Exception as e:
        logger.error(f"Failed to index to Meilisearch: {e}")


class AlertingHandler:
    """
    Handler for triggering alerts based on event patterns.
    """
    
    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
    
    def add_rule(
        self,
        name: str,
        event_type: Optional[str] = None,
        service_id: Optional[str] = None,
        callback: Optional[Callable] = None
    ):
        """
        Add an alerting rule.
        
        Args:
            name: Rule name
            event_type: Match this event type (None = any)
            service_id: Match this service (None = any)
            callback: Async function to call on match
        """
        self.rules.append({
            'name': name,
            'event_type': event_type,
            'service_id': service_id,
            'callback': callback
        })
    
    async def __call__(self, event: Dict[str, Any]):
        """Process event against rules."""
        for rule in self.rules:
            if self._matches(event, rule):
                logger.warning(f"Alert triggered: {rule['name']} for event {event}")
                if rule['callback']:
                    await rule['callback'](event, rule)
    
    def _matches(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if event matches rule criteria."""
        if rule['event_type'] and event.get('event_type') != rule['event_type']:
            return False
        if rule['service_id'] and event.get('service_id') != rule['service_id']:
            return False
        return True


# ============================================================================
# Consumer Runner
# ============================================================================

async def run_consumer(handlers: Optional[List[Callable]] = None):
    """
    Run the event consumer with specified handlers.
    
    Args:
        handlers: List of handler functions. Uses defaults if not specified.
    """
    consumer = EventConsumer()
    
    # Register handlers
    if handlers:
        for handler in handlers:
            consumer.add_handler(handler)
    else:
        # Default handlers
        consumer.add_handler(log_event_handler)
        if settings.meilisearch_url:
            consumer.add_handler(meilisearch_indexer)
    
    try:
        await consumer.start()
    except KeyboardInterrupt:
        logger.info("Shutting down consumer...")
    finally:
        await consumer.stop()


if __name__ == "__main__":
    # Run as standalone script
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_consumer())
