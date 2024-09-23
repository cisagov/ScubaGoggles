"""
ScubaGoggles setuptools
"""
from setuptools import setup, find_packages

setup(name='scubagoggles',
      version='0.3.0',
      description='SCuBA security baseline assessment tool',
      author='CISA',
      packages=find_packages(exclude=['__pycache__']),
      package_data = {
        'scubagoggles': ['reporter/**/*']
      },
      include_package_data=True,
      python_requires='>=3.10.0',
      install_requires=[
        'google-api-python-client==2.142.0',
        'google-auth-httplib2==0.2.0',
        'google-auth-oauthlib==1.2.1',
        'MarkupSafe==2.1.5',
        'dnspython==2.6.1',
        'pandas==2.2.0',
        'tqdm==4.66.5',
        'requests==2.32.3',
        'pyyaml==6.0.2'
      ],
      entry_points={
          'console_scripts': ['scubagoggles=scubagoggles.main:dive']
      }
    )
