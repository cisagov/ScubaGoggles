"""
ScubaGoggles setuptools
"""
from setuptools import setup, find_packages

setup(name='scubagoggles',
      version='0.1.0',
      description='SCuBA security baseline assessment tool',
      author='CISA',
      packages=find_packages(exclude=['__pycache__']),
      package_data = {
        'scubagoggles': ['reporter/**/*']
      },
      include_package_data=True,
      python_requires='>=3.7.16',
      install_requires=[
        'google-api-python-client==1.7.9',
        'google-auth-httplib2==0.0.3',
        'google-auth-oauthlib==0.4.0',
        'MarkupSafe==2.1.1',
        'dnspython==2.6.1',
        'pandas==1.5.0',
        'tqdm==4.64.1',
        'requests==2.31.0'
      ],
      entry_points={
          'console_scripts': ['scubagoggles=scubagoggles.main:dive']
      }
    )
