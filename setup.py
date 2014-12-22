from setuptools import setup, find_packages

setup(
    name='sniffmypacketsv2',
    author='catalyst256',
    version='1.0',
    author_email='catalyst256@gmail.com',
    description='Maltego transforms for pcap analysis and more',
    license='GPL',
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    zip_safe=False,
    package_data={
        '' : [ '*.gif', '*.png', '*.conf', '*.mtz', '*.machine' ] # list of resources
    },
    install_requires=[
        'canari>=1.1',
        'pymongo>=2.7.2',
        'scapy',
        'magic',
        'pygeoip',
        'requests'
    ],
    dependency_links=[
        # custom links for the install_requires
    ]
)
