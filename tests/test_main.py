import asyncio
import unittest
from main import run_payload_tests

# A dummy fuzz function that returns a result only for a specific payload.
async def dummy_fuzz(session, url, param, payload):
    # We ignore the session and other parameters for this dummy test.
    if payload == "valid":
        return {
            "url": url,
            "parameter": param,
            "payload": payload,
            "method": "GET",
            "similarity": 0.5,
            "nuclei_output": "dummy_nuclei"
        }
    return None

# A dummy session object for the purpose of testing.
class DummySession:
    pass

class TestMainMethods(unittest.TestCase):
    def test_run_payload_tests(self):
        session = DummySession()
        url = "http://example.com"
        param = "id"
        payloads = ["invalid", "valid", "another"]
        result = asyncio.run(run_payload_tests(session, dummy_fuzz, url, param, payloads))
        self.assertIsNotNone(result)
        self.assertEqual(result["payload"], "valid")

if __name__ == "__main__":
    unittest.main() 