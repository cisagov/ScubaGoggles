"""
Secure Cloud Business Applications (SCuBA)
https://cisa.gov/scuba

scuba.py a script that imports and runs the scubagoggles
package
"""

# lets us import files from the scubagoggles folder
import sys
sys.path.insert(1, './scubagoggles')

# However, pylint doesn't like this
from scubagoggles.main import dive # pylint: disable=import-error wrong-import-position

def main():
    """
    SCuBA
    """
    dive()

if __name__ == '__main__':
    main()
