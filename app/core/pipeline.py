from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from fastapi import Request

class SecurityException(Exception):
    def __init__(self, message: str, driver: str):
        self.message = message
        self.driver = driver
        super().__init__(message)

class BaseDriver(ABC):
    """
    Abstract Base Class for all Security Drivers (The Legos).
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    async def process_request(self, req_body: bytes, headers: Dict) -> bytes:
        """
        Inspect and optionally modify the request before it goes upstream.
        Raise SecurityException to block.
        Return modified body (for redaction).
        """
        pass

    @abstractmethod
    async def process_response(self, res_body: bytes) -> bytes:
        """
        Inspect and optionally modify the response coming back from LLM.
        """
        pass

    def _flag_violation(self, message: str, driver_name: str):
        """
        Handles a security violation based on the Configured Mode.
        - strict: Raises SecurityException (Blocks)
        - audit: Logs warning (Allows)
        - interactive: Asks User (Allow/Block)
        """
        mode = self.config.get("mode", "strict")
        
        if mode == "audit":
            print(f"⚠️ [AUDIT] would have blocked: {message} ({driver_name})")
            return
        
        # Default: Block
        raise SecurityException(message, driver=driver_name)

class SafetyPipeline:
    """
    The Manager. Runs a list of drivers in sequence.
    """
    def __init__(self):
        self.drivers: List[BaseDriver] = []

    def add_driver(self, driver: BaseDriver):
        self.drivers.append(driver)

    async def run_request(self, body: bytes, headers: Dict) -> bytes:
        current_body = body
        for driver in self.drivers:
            # Pass output of previous driver as input to next (Cascade)
            current_body = await driver.process_request(current_body, headers)
        return current_body

    async def run_response(self, body: bytes) -> bytes:
        current_body = body
        for driver in self.drivers:
            current_body = await driver.process_response(current_body)
        return current_body
