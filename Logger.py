import datetime
import logging
import os
import sys

LOGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


class Logger(logging.Logger):

    def __init__(self, name="logger", consoleOut=False):
        super().__init__(name)
        self.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d | %(levelname)s | [%(module)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        now = datetime.datetime.now()
        self.outputFile = f"{LOGS_PATH}/{self.name}_{now.strftime('%Y-%m-%d')}.log"
        if not os.path.exists(LOGS_PATH):
            os.makedirs(LOGS_PATH)
        fileHandler = logging.FileHandler(self.outputFile)
        fileHandler.setFormatter(self.formatter)
        self.addHandler(fileHandler)
        if consoleOut:
            streamHandler = logging.StreamHandler(sys.stdout)
            streamHandler.setFormatter(self.formatter)
            self.addHandler(streamHandler)
