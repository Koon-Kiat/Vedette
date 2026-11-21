from vedette.pipeline.queue import MemoryQueue


async def test_messages_come_out_in_publish_order() -> None:
    queue: MemoryQueue[str] = MemoryQueue()
    await queue.publish("a")
    await queue.publish("b")
    await queue.publish("c")

    messages = await queue.consume(max_items=10, wait_seconds=0.01)

    assert [m.payload for m in messages] == ["a", "b", "c"]
    assert len({m.id for m in messages}) == 3


async def test_publish_returns_the_id_the_consumer_sees() -> None:
    queue: MemoryQueue[str] = MemoryQueue()

    published_id = await queue.publish("a")
    (message,) = await queue.consume(max_items=1, wait_seconds=0.01)

    assert message.id == published_id


async def test_consume_returns_at_most_max_items() -> None:
    queue: MemoryQueue[int] = MemoryQueue()
    for n in range(5):
        await queue.publish(n)

    first = await queue.consume(max_items=2, wait_seconds=0.01)
    rest = await queue.consume(max_items=10, wait_seconds=0.01)

    assert [m.payload for m in first] == [0, 1]
    assert [m.payload for m in rest] == [2, 3, 4]


async def test_consume_on_an_empty_queue_times_out_with_nothing() -> None:
    queue: MemoryQueue[str] = MemoryQueue()

    assert await queue.consume(max_items=5, wait_seconds=0.01) == []


async def test_depth_counts_messages_until_they_are_acknowledged() -> None:
    queue: MemoryQueue[str] = MemoryQueue()
    await queue.publish("a")
    await queue.publish("b")
    assert await queue.depth() == 2

    messages = await queue.consume(max_items=10, wait_seconds=0.01)
    assert await queue.depth() == 2

    await queue.ack([messages[0].id])
    assert await queue.depth() == 1

    await queue.ack([messages[1].id])
    assert await queue.depth() == 0


async def test_acknowledging_an_unknown_id_is_harmless() -> None:
    queue: MemoryQueue[str] = MemoryQueue()
    await queue.publish("a")

    await queue.ack(["no-such-id"])

    assert await queue.depth() == 1
