"""Retry utilities for robust network operations."""

import asyncio
import logging
import random
from typing import Any, Callable, List, Optional, Type, Union

from ..exceptions import NetworkError, RateLimitError

logger = logging.getLogger(__name__)


class RetryConfig:
    """Configuration for retry behavior."""
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        backoff_factor: float = 1.0
    ) -> None:
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.backoff_factor = backoff_factor


async def async_retry(
    func: Callable[..., Any],
    *args: Any,
    config: Optional[RetryConfig] = None,
    retryable_exceptions: Optional[List[Type[Exception]]] = None,
    **kwargs: Any
) -> Any:
    """Retry an async function with exponential backoff.
    
    Args:
        func: Async function to retry
        *args: Arguments for the function
        config: Retry configuration
        retryable_exceptions: List of exceptions that should trigger retry
        **kwargs: Keyword arguments for the function
    
    Returns:
        Result of the function call
        
    Raises:
        The last exception if all retries fail
    """
    if config is None:
        config = RetryConfig()
    
    if retryable_exceptions is None:
        retryable_exceptions = [NetworkError, asyncio.TimeoutError, ConnectionError]
    
    last_exception = None
    
    for attempt in range(config.max_attempts):
        try:
            result = await func(*args, **kwargs)
            if attempt > 0:
                logger.info(f"Retry succeeded on attempt {attempt + 1}")
            return result
            
        except Exception as e:
            last_exception = e
            
            # Check if this exception should trigger a retry
            if not any(isinstance(e, exc_type) for exc_type in retryable_exceptions):
                logger.debug(f"Non-retryable exception: {type(e).__name__}: {e}")
                raise e
            
            # Don't retry on the last attempt
            if attempt == config.max_attempts - 1:
                logger.error(f"All {config.max_attempts} retry attempts failed")
                break
            
            # Calculate delay
            delay = calculate_delay(attempt, config)
            
            # Handle rate limiting specially
            if isinstance(e, RateLimitError) and e.retry_after:
                delay = max(delay, e.retry_after)
                logger.warning(f"Rate limited. Waiting {delay}s before retry (attempt {attempt + 1}/{config.max_attempts})")
            else:
                logger.warning(f"Retrying in {delay:.1f}s due to {type(e).__name__}: {e} (attempt {attempt + 1}/{config.max_attempts})")
            
            await asyncio.sleep(delay)
    
    # All retries failed, raise the last exception
    if last_exception:
        raise last_exception
    else:
        raise RuntimeError("Unexpected retry loop completion")


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay for retry attempt with exponential backoff and jitter."""
    # Exponential backoff
    delay = config.base_delay * (config.exponential_base ** attempt) * config.backoff_factor
    
    # Cap at max delay
    delay = min(delay, config.max_delay)
    
    # Add jitter to avoid thundering herd
    if config.jitter:
        jitter_amount = delay * 0.1  # 10% jitter
        delay += random.uniform(-jitter_amount, jitter_amount)
    
    return max(delay, 0.1)  # Minimum 100ms delay


class CircuitBreaker:
    """Circuit breaker pattern for failing services."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: float = 60.0,
        expected_exception: Type[Exception] = Exception
    ) -> None:
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Call function through circuit breaker."""
        import time
        
        if self.state == "OPEN":
            if time.time() - (self.last_failure_time or 0) > self.timeout:
                self.state = "HALF_OPEN"
                logger.info("Circuit breaker transitioning to HALF_OPEN")
            else:
                raise NetworkError("Circuit breaker is OPEN - service unavailable")
        
        try:
            result = await func(*args, **kwargs)
            
            # Success - reset circuit breaker
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
                logger.info("Circuit breaker reset to CLOSED")
            
            return result
            
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
            
            raise e