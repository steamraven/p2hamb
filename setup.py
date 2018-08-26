from setuptools import setup

setup(
    name='p2hamb_client',
    version='0.1',
    py_modules=['p2hamb_client'],
    install_requires=[
        'Click',
        'hbmqtt'
    ],
    entry_points='''
        [console_scripts]
        p2hamb_client=p2hamb_client:cli
    ''',
)
