"""
Advanced retry handler with multiple backoff strategies and comprehensive error handling.
"""
import asyncio
import logging
import random
import time
from typing import Callable, Any, Optional, Type, Union, List
from dataclasses import dataclass
from functools import wraps

@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_retries: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    backoff_factor: float = 2.0
    jitter: bool = True
    retry_exceptions: List[Type[Exception]] = None
    retry_on_status_codes: List[int] = None

    def __post_init__(self):
        if self.retry_exceptions is None:
            self.retry_exceptions = [
                ConnectionError,
                TimeoutError,
                asyncio.TimeoutError,
            ]
        if self.retry_on_status_codes is None:
            self.retry_on_status_codes = [429, 500, 502, 503, 504]

class RetryHandler:
    """Advanced retry handler with multiple backoff strategies"""
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self.logger = logging.getLogger(__name__)

    def calculate_delay(self, attempt: int, strategy: str = 'exponential') -> float:
        """
        Calculate delay using different backoff strategies:
        - exponential: Exponential backoff with optional jitter
        - linear: Linear backoff with optional jitter
        - fibonacci: Fibonacci backoff with optional jitter
        """
        if strategy == 'exponential':
            delay = min(
                self.config.initial_delay * (self.config.backoff_factor ** (attempt - 1)),
                self.config.max_delay
            )
        elif strategy == 'linear':
            delay = min(
                self.config.initial_delay * attempt,
                self.config.max_delay
            )
        elif strategy == 'fibonacci':
            def fib(n: int) -> int:
                if n <= 0:
                    return 0
                elif n == 1:
                    return 1
                return fib(n - 1) + fib(n - 2)
            delay = min(
                self.config.initial_delay * fib(attempt),
                self.config.max_delay
            )
        else:
            raise ValueError(f"Unknown backoff strategy: {strategy}")

        if self.config.jitter:
            delay = random.uniform(0.5 * delay, 1.5 * delay)

        return delay

    async def sleep_with_jitter(self, delay: float):
        """Sleep with jitter to avoid thundering herd problem"""
        if self.config.jitter:
            jitter = random.uniform(-0.1 * delay, 0.1 * delay)
            delay += jitter
        await asyncio.sleep(delay)

    def should_retry(self, exception: Optional[Exception] = None, status_code: Optional[int] = None) -> bool:
        """Determine if a retry should be attempted based on the exception or status code"""
        if exception is not None:
            return any(isinstance(exception, exc_type) for exc_type in self.config.retry_exceptions)
        if status_code is not None:
            return status_code in self.config.retry_on_status_codes
        return False

    def retry(self, strategy: str = 'exponential'):
        """Decorator for retrying async functions with specified strategy"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                last_exception = None
                attempt = 1

                while attempt <= self.config.max_retries + 1:
                    try:
                        result = await func(*args, **kwargs)

                        # Check status code for HTTP responses
                        status_code = getattr(result, 'status', None)
                        if status_code and self.should_retry(status_code=status_code):
                            raise RetryableStatusCode(f"Received status code {status_code}")

                        return result

                    except Exception as e:
                        last_exception = e
                        should_retry = self.should_retry(exception=e)

                        if not should_retry or attempt > self.config.max_retries:
                            break

                        delay = self.calculate_delay(attempt, strategy)
                        self.logger.warning(
                            "Attempt %d/%d failed: %s. Retrying in %.2f seconds...",
                            attempt, self.config.max_retries, str(e), delay
                        )
                        await self.sleep_with_jitter(delay)
                        attempt += 1

                if last_exception:
                    raise last_exception
            return wrapper
        return decorator

class RetryableStatusCode(Exception):
    """Exception raised when a retryable status code is received"""
    pass

class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_timeout: float = 5.0
    ):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_timeout = half_open_timeout
        self.failures = 0
        self.last_failure_time = 0
        self.state = 'closed'

    def should_execute(self) -> bool:
        """Determine if the protected code should be executed"""
        now = time.time()

        if self.state == 'open':
            if now - self.last_failure_time >= self.reset_timeout:
                self.state = 'half-open'
                return True
            return False
        
        if self.state == 'half-open':
            return now - self.last_failure_time >= self.half_open_timeout
        
        return True

    def record_success(self):
        """Record a successful execution"""
        self.failures = 0
        self.state = 'closed'

    def record_failure(self):
        """Record a failed execution"""
        self.failures += 1
        self.last_failure_time = time.time()
        
        if self.failures >= self.failure_threshold:
            self.state = 'open'

    def __call__(self, func: Callable):
        """Decorator for protecting functions with circuit breaker"""
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not self.should_execute():
                raise CircuitBreakerOpen("Circuit breaker is open")
            
            try:
                result = await func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure()
                raise e
        return wrapper

class CircuitBreakerOpen(Exception):
    """Exception raised when circuit breaker is open"""
    pass