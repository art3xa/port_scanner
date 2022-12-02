from dataclasses import dataclass
from typing import Dict, Set


@dataclass
class DataArguments:
    """
    This class is used to store all the data arguments
    """
    ip: str
    ports: Dict[str, Set[int]]
    timeout: float
    verbose: bool
    guess: bool
    threads: int
