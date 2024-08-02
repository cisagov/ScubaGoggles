"""
The Browser class encapsulates the setup, usage, and teardown of a
Selenium WebDriver instance for automated browser interactions.
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class Browser:
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        self.driver = webdriver.Chrome(options=chrome_options)

    def get(self, url):
        self.driver.get(url)
    
    def quit(self):
        self.driver.quit()
    
    def find_element(self, by, value):
        return self.driver.find_element(by, value)
    
    def find_elements(self, by, value):
        return self.driver.find_elements(by, value)

    def current_url(self):
        return self.driver.current_url