from task1 import rate_limit
import time

def test_rate_limit():
    global last_request_time

    # Step 1: Simulate the first call (should not trigger rate limit)
    last_request_time = 0  # Reset the global variable
    assert rate_limit() == True  # The first call should pass immediately

    # Step 2: Simulate a second call within the rate limit period
    last_request_time = time.time()  # Set the last request to the current time
    assert rate_limit() == False  # This call should trigger the rate limit

    # Step 3: Simulate waiting for the rate limit to expire
    time.sleep(1)  # Shorter than the actual rate limit (mocking the logic)
    last_request_time -= 30  # Adjust the last request time to simulate expiry
    assert rate_limit() == True  # This call should pass after the "expiry"
