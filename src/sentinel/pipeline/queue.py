"""Queue abstraction joining the pipeline stages.

Stages talk only to :class:`EventQueue`, so the in-process queue used on one
machine can later be swapped for Redis Streams without touching them. The
contract is at-least-once: a message stays counted in :meth:`EventQueue.depth`
until the consumer acknowledges it.
"""

import asyncio
import itertools
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Message[T]:
    """A queued payload together with the id used to acknowledge it."""

    id: str
    payload: T


class EventQueue[T](ABC):
    """A queue of work items passed from one pipeline stage to the next."""

    @abstractmethod
    async def publish(self, payload: T) -> str:
        """Add a payload and return the id of the message created for it."""

    @abstractmethod
    async def consume(self, max_items: int, wait_seconds: float) -> list[Message[T]]:
        """Return up to ``max_items`` messages, oldest first.

        Waits up to ``wait_seconds`` seconds for the first message and returns an
        empty list if none arrives.
        """

    @abstractmethod
    async def ack(self, message_ids: Iterable[str]) -> None:
        """Mark messages as fully processed. Unknown ids are ignored."""

    @abstractmethod
    async def depth(self) -> int:
        """Number of messages published but not yet acknowledged."""


class MemoryQueue[T](EventQueue[T]):
    """In-process queue for a single-machine deployment. Not durable."""

    def __init__(self) -> None:
        """Create an empty queue."""
        self._pending: asyncio.Queue[Message[T]] = asyncio.Queue()
        self._unacked: dict[str, Message[T]] = {}
        self._ids = itertools.count(1)

    async def publish(self, payload: T) -> str:
        """Add a payload and return the id of the message created for it."""
        message = Message(id=str(next(self._ids)), payload=payload)
        await self._pending.put(message)
        return message.id

    async def consume(self, max_items: int, wait_seconds: float) -> list[Message[T]]:
        """Return up to ``max_items`` messages, waiting ``wait_seconds`` for the first."""
        try:
            async with asyncio.timeout(wait_seconds):
                first = await self._pending.get()
        except TimeoutError:
            return []
        messages = [first]
        while len(messages) < max_items and not self._pending.empty():
            messages.append(self._pending.get_nowait())
        for message in messages:
            self._unacked[message.id] = message
        return messages

    async def ack(self, message_ids: Iterable[str]) -> None:
        """Mark messages as fully processed. Unknown ids are ignored."""
        for message_id in message_ids:
            self._unacked.pop(message_id, None)

    async def depth(self) -> int:
        """Number of messages published but not yet acknowledged."""
        return self._pending.qsize() + len(self._unacked)
