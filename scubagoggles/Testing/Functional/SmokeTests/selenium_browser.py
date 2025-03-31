"""
selenium_browser.py declares a Browser class for use in ScubaGoggles testing.
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


class Browser:
    """
    The Browser class encapsulates the setup, usage, and teardown of a
    Selenium WebDriver instance for automated browser interactions.
    """
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument('--headless=new')
        chrome_options.add_argument('--log-level=3')
        chrome_options.add_argument('--window-size=1200,800')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')

        self.driver = webdriver.Chrome(options=chrome_options)

    def get(self, url):
        """
        Load a new web page in the current browser window.

        Args:
            url: The URL to load. Must be a fully qualified URL
        """
        self.driver.get(url)

    def quit(self):
        """
        Quits the driver, closing every associated window.
        """
        self.driver.quit()

    def find_element(self, by, value):
        """
        Find the first WebElement using the given method. This method is
        affected by the 'implicit wait' times in force at the time and
        execution. The find_element(...) invocation will return a matching
        row, or try again repeatedly until the configured timeout is reached.

        Args:
            by: The locating mechanism to use, i.e. By.CLASS_NAME, By.TAG_NAME
            value: The locator, i.e. "h1", "header"

        Returns:
            WebElement: The first matching element on the current page
        """
        return self.driver.find_element(by, value)

    def find_elements(self, by, value):
        """
        Find all WebElements within the current page. This method is affected
        by the 'implicit wait' times in force at the time and execution. The
        find_elements(...) invocation will return as soon as there are more
        than 0 items in the found collection, or will return an empty list of
        the timeout is reached.

        Args:
            by: The locating mechanism to use, i.e. By.CLASS_NAME, By.TAG_NAME
            value: The locator, i.e. "h1", "header"

        Returns:
            WebElement: A list of all matching WebElements, or an empty list
            if nothing matches
        """
        return self.driver.find_elements(by, value)

    def current_url(self):
        """
        Get a string representing the current URL that the browser is looking
        at.

        Returns:
            The URL of the page currently loaded in the browser
        """
        return self.driver.current_url
