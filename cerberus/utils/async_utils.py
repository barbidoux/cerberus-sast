"""
Common async utilities for Cerberus SAST.

Provides:
- Retry policies with exponential backoff
- Concurrent task execution with limits
- Timeout decorators
- Progress tracking utilities
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from functools import wraps
from typing import (
    Any,
    Awaitable,
    Callable,
    Generic,
    Optional,
    TypeVar,
)

from cerberus.utils.logging import ComponentLogger

T = TypeVar("T")
logger = ComponentLogger("async_utils")


@dataclass
class RetryPolicy:
    """
    Configurable retry policy with exponential backoff.

    Attributes:
        max_attempts: Maximum number of retry attempts
        backoff_factor: Multiplier for exponential backoff
        max_backoff: Maximum wait time between retries
        retryable_exceptions: Tuple of exception types to retry on
    """

    max_attempts: int = 3
    backoff_factor: float = 2.0
    max_backoff: float = 60.0
    retryable_exceptions: tuple[type[Exception], ...] = field(
        default_factory=lambda: (TimeoutError, ConnectionError, OSError)
    )

    async def execute(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """
        Execute an async function with retry logic.

        Args:
            func: Async function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            Result of the function

        Raises:
            Exception: The last exception if all retries fail
        """
        last_exception: Optional[Exception] = None

        for attempt in range(self.max_attempts):
            try:
                return await func(*args, **kwargs)
            except self.retryable_exceptions as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    wait_time = min(
                        self.backoff_factor ** attempt,
                        self.max_backoff,
                    )
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_attempts} failed, "
                        f"retrying in {wait_time:.1f}s",
                        error=str(e),
                    )
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(
                        f"All {self.max_attempts} attempts failed",
                        error=str(e),
                    )

        if last_exception:
            raise last_exception
        raise RuntimeError("Retry policy exhausted without exception")


async def gather_with_concurrency(
    n: int,
    tasks: list[Callable[[], Awaitable[T]]],
    return_exceptions: bool = False,
) -> list[T]:
    """
    Execute async tasks with limited concurrency.

    Args:
        n: Maximum number of concurrent tasks
        tasks: List of async task factories (callables that return awaitables)
        return_exceptions: If True, return exceptions instead of raising

    Returns:
        List of results in the same order as tasks
    """
    semaphore = asyncio.Semaphore(n)

    async def limited_task(task: Callable[[], Awaitable[T]]) -> T:
        async with semaphore:
            return await task()

    return await asyncio.gather(
        *[limited_task(t) for t in tasks],
        return_exceptions=return_exceptions,
    )


async def gather_dict(
    tasks: dict[str, Awaitable[T]],
    return_exceptions: bool = False,
) -> dict[str, T]:
    """
    Execute async tasks and return results as a dictionary.

    Args:
        tasks: Dictionary mapping keys to awaitables
        return_exceptions: If True, return exceptions instead of raising

    Returns:
        Dictionary mapping keys to results
    """
    keys = list(tasks.keys())
    results = await asyncio.gather(
        *tasks.values(),
        return_exceptions=return_exceptions,
    )
    return dict(zip(keys, results))


def async_timeout(seconds: float) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """
    Decorator to add timeout to async functions.

    Args:
        seconds: Timeout in seconds

    Returns:
        Decorated function with timeout

    Raises:
        asyncio.TimeoutError: If the function exceeds the timeout
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            return await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=seconds,
            )
        return wrapper
    return decorator


def run_async(coro: Awaitable[T]) -> T:
    """
    Run an async function synchronously.

    Useful for CLI commands that need to call async code.

    Args:
        coro: Coroutine to execute

    Returns:
        Result of the coroutine
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        # If already in an event loop, use nest_asyncio pattern
        import nest_asyncio
        nest_asyncio.apply()
        return loop.run_until_complete(coro)
    else:
        return asyncio.run(coro)


@dataclass
class ProgressTracker(Generic[T]):
    """
    Track progress of async operations.

    Attributes:
        total: Total number of items to process
        completed: Number of completed items
        failed: Number of failed items
        results: List of results
    """

    total: int
    completed: int = 0
    failed: int = 0
    results: list[T] = field(default_factory=list)
    errors: list[Exception] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def update(
        self,
        result: Optional[T] = None,
        error: Optional[Exception] = None,
    ) -> None:
        """Update progress with a result or error."""
        async with self._lock:
            if error:
                self.failed += 1
                self.errors.append(error)
            else:
                self.completed += 1
                if result is not None:
                    self.results.append(result)

    @property
    def progress(self) -> float:
        """Get progress as a percentage."""
        if self.total == 0:
            return 100.0
        return ((self.completed + self.failed) / self.total) * 100

    @property
    def is_complete(self) -> bool:
        """Check if all items have been processed."""
        return (self.completed + self.failed) >= self.total


async def process_with_progress(
    items: list[T],
    processor: Callable[[T], Awaitable[Any]],
    concurrency: int = 10,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> ProgressTracker[Any]:
    """
    Process items with progress tracking.

    Args:
        items: List of items to process
        processor: Async function to process each item
        concurrency: Maximum concurrent operations
        on_progress: Optional callback for progress updates (completed, total)

    Returns:
        ProgressTracker with results and errors
    """
    tracker = ProgressTracker[Any](total=len(items))
    semaphore = asyncio.Semaphore(concurrency)

    async def process_item(item: T) -> None:
        async with semaphore:
            try:
                result = await processor(item)
                await tracker.update(result=result)
            except Exception as e:
                await tracker.update(error=e)

            if on_progress:
                on_progress(tracker.completed + tracker.failed, tracker.total)

    await asyncio.gather(*[process_item(item) for item in items])
    return tracker


class RateLimiter:
    """
    Rate limiter for API calls.

    Uses a token bucket algorithm to limit the rate of operations.
    """

    def __init__(self, rate: float, burst: int = 1):
        """
        Initialize rate limiter.

        Args:
            rate: Maximum operations per second
            burst: Maximum burst size (tokens in bucket)
        """
        self.rate = rate
        self.burst = burst
        self._tokens = burst
        self._last_update = asyncio.get_event_loop().time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_update
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_update = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1

    async def __aenter__(self) -> "RateLimiter":
        """Async context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        pass


class AsyncCache(Generic[T]):
    """
    Simple async-safe cache with TTL.

    Thread-safe cache for async operations with automatic expiration.
    """

    def __init__(self, ttl: float = 300.0):
        """
        Initialize cache.

        Args:
            ttl: Time-to-live in seconds for cache entries
        """
        self.ttl = ttl
        self._cache: dict[str, tuple[T, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[T]:
        """Get value from cache if not expired."""
        async with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if asyncio.get_event_loop().time() - timestamp < self.ttl:
                    return value
                del self._cache[key]
            return None

    async def set(self, key: str, value: T) -> None:
        """Set value in cache."""
        async with self._lock:
            self._cache[key] = (value, asyncio.get_event_loop().time())

    async def get_or_set(
        self,
        key: str,
        factory: Callable[[], Awaitable[T]],
    ) -> T:
        """Get value from cache or compute and cache it."""
        value = await self.get(key)
        if value is not None:
            return value

        value = await factory()
        await self.set(key, value)
        return value

    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()

    async def remove(self, key: str) -> bool:
        """Remove a specific key from cache."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
