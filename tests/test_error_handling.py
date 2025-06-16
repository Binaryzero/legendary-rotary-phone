"""Test error handling and retry logic."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False
    
    # Mock pytest decorators
    class pytest:
        @staticmethod
        def mark(*args, **kwargs):
            def decorator(func):
                return func
            return decorator
        
        @staticmethod
        def raises(*args, **kwargs):
            class RaisesContext:
                def __init__(self, expected_exception, match=None):
                    self.expected_exception = expected_exception
                    self.match = match
                    self.value = None
                
                def __enter__(self):
                    return self
                
                def __exit__(self, exc_type, exc_val, exc_tb):
                    if exc_type is None:
                        raise AssertionError(f"Expected {self.expected_exception.__name__} but no exception was raised")
                    if not issubclass(exc_type, self.expected_exception):
                        return False  # Re-raise
                    self.value = exc_val
                    return True  # Suppress exception
            
            return RaisesContext(*args, **kwargs)

from odin import exceptions
from odin.utils.retry import async_retry, RetryConfig, CircuitBreaker
from odin.connectors.cve_project import CVEProjectConnector


class TestExceptions:
    """Test custom exception classes."""
    
    def test_cve_research_error_base(self):
        """Test base exception class."""
        exc = exceptions.CVEResearchError("Test message", cve_id="CVE-2021-44228", source="TestSource")
        assert str(exc) == "Test message | CVE: CVE-2021-44228 | Source: TestSource"
        assert exc.cve_id == "CVE-2021-44228"
        assert exc.source == "TestSource"
    
    def test_network_error_with_status(self):
        """Test network error with status code."""
        exc = exceptions.NetworkError("Connection failed", status_code=500, cve_id="CVE-2021-44228")
        assert exc.status_code == 500
        assert "Connection failed" in str(exc)
    
    def test_rate_limit_error(self):
        """Test rate limit error with retry_after."""
        exc = exceptions.RateLimitError("Rate limited", retry_after=120, cve_id="CVE-2021-44228")
        assert exc.retry_after == 120
        assert exc.status_code == 429
    
    def test_dependency_error(self):
        """Test dependency error."""
        exc = exceptions.DependencyError("pandas")
        assert exc.dependency == "pandas"
        assert "Required dependency 'pandas' is not available" in str(exc)


class TestRetryLogic:
    """Test retry utilities."""
    
    @pytest.mark.asyncio
    async def test_successful_first_attempt(self):
        """Test function succeeds on first attempt."""
        async def success_func():
            return "success"
        
        result = await async_retry(success_func)
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_retry_on_network_error(self):
        """Test retry on network errors."""
        call_count = 0
        
        async def failing_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise exceptions.NetworkError("Connection failed")
            return "success after retries"
        
        config = RetryConfig(max_attempts=3, base_delay=0.1)
        result = await async_retry(failing_func, config=config)
        
        assert result == "success after retries"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_non_retryable_exception(self):
        """Test that non-retryable exceptions are not retried."""
        call_count = 0
        
        async def failing_func():
            nonlocal call_count
            call_count += 1
            raise ValueError("Non-retryable error")
        
        config = RetryConfig(max_attempts=3)
        
        with pytest.raises(ValueError):
            await async_retry(failing_func, config=config)
        
        assert call_count == 1  # Should not retry
    
    @pytest.mark.asyncio
    async def test_rate_limit_retry_after(self):
        """Test rate limit handling with retry_after."""
        call_count = 0
        
        async def rate_limited_func():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise exceptions.RateLimitError("Rate limited", retry_after=0.1)
            return "success"
        
        config = RetryConfig(max_attempts=2, base_delay=0.05)
        result = await async_retry(rate_limited_func, config=config)
        
        assert result == "success"
        assert call_count == 2


class TestCircuitBreaker:
    """Test circuit breaker functionality."""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_state(self):
        """Test circuit breaker in closed state (normal operation)."""
        circuit = CircuitBreaker(failure_threshold=3, timeout=1.0)
        
        async def success_func():
            return "success"
        
        result = await circuit.call(success_func)
        assert result == "success"
        assert circuit.state == "CLOSED"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker opens after threshold failures."""
        circuit = CircuitBreaker(failure_threshold=2, timeout=1.0)
        
        async def failing_func():
            raise exceptions.NetworkError("Service unavailable")
        
        # First failure
        with pytest.raises(exceptions.NetworkError):
            await circuit.call(failing_func)
        assert circuit.state == "CLOSED"
        
        # Second failure - should open circuit
        with pytest.raises(exceptions.NetworkError):
            await circuit.call(failing_func)
        assert circuit.state == "OPEN"
        
        # Third call should fail immediately due to open circuit
        with pytest.raises(exceptions.NetworkError, match="Circuit breaker is OPEN"):
            await circuit.call(failing_func)


class TestEnhancedConnector:
    """Test enhanced CVE Project connector with error handling."""
    
    def test_invalid_cve_format(self):
        """Test handling of invalid CVE format."""
        connector = CVEProjectConnector()
        
        with pytest.raises(exceptions.ParseError, match="Invalid CVE ID format"):
            asyncio.run(connector.fetch("INVALID-CVE", Mock()))
    
    def test_invalid_cve_number(self):
        """Test handling of invalid CVE number."""
        connector = CVEProjectConnector()
        
        with pytest.raises(exceptions.ParseError, match="Invalid CVE number"):
            asyncio.run(connector.fetch("CVE-2021-INVALID", Mock()))
    
    @pytest.mark.asyncio
    async def test_rate_limit_handling(self):
        """Test rate limit response handling."""
        connector = CVEProjectConnector()
        
        # Mock session with rate limit response
        mock_response = Mock()
        mock_response.status = 429
        mock_response.headers = {'Retry-After': '60'}
        
        mock_session = Mock()
        mock_session.get = Mock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)
        
        with pytest.raises(exceptions.RateLimitError) as exc_info:
            await connector._fetch_with_session(mock_session, "http://test.com", "CVE-2021-44228")
        
        assert exc_info.value.retry_after == 60
        assert exc_info.value.status_code == 429
    
    @pytest.mark.asyncio 
    async def test_server_error_handling(self):
        """Test server error response handling."""
        connector = CVEProjectConnector()
        
        # Mock session with server error
        mock_response = Mock()
        mock_response.status = 500
        
        mock_session = Mock()
        mock_session.get = Mock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)
        
        with pytest.raises(exceptions.NetworkError) as exc_info:
            await connector._fetch_with_session(mock_session, "http://test.com", "CVE-2021-44228")
        
        assert exc_info.value.status_code == 500
        assert "Server error" in str(exc_info.value)
    
    def test_parse_error_handling(self):
        """Test parse error handling."""
        connector = CVEProjectConnector()

        # Parsing malformed data should not raise but return empty fields
        malformed_data = {"invalid": "structure"}

        result = connector.parse("CVE-2021-44228", malformed_data)
        assert isinstance(result, dict)


if __name__ == "__main__":
    # Run tests manually if pytest not available
    import traceback
    
    print("Testing Error Handling and Retry Logic")
    print("=" * 50)
    
    test_classes = [TestExceptions, TestRetryLogic, TestCircuitBreaker, TestEnhancedConnector]
    passed = 0
    failed = 0
    
    for test_class in test_classes:
        print(f"\n--- {test_class.__name__} ---")
        instance = test_class()
        
        for method_name in dir(instance):
            if method_name.startswith('test_'):
                try:
                    method = getattr(instance, method_name)
                    if asyncio.iscoroutinefunction(method):
                        asyncio.run(method())
                    else:
                        method()
                    print(f"✓ {method_name}")
                    passed += 1
                except Exception as e:
                    print(f"✗ {method_name}: {e}")
                    traceback.print_exc()
                    failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("All error handling tests passed!")
    else:
        print("Some tests failed. See details above.")