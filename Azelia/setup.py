from setuptools import setup, find_packages

setup(
    name="your_package_name",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "argon2-cffi==21.1.0",
        "bcrypt==3.2.0",
        "mysql-connector-python==8.0.27",
    ],
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author="john chris",
    author_email="idiomajohnchris049@gmail.com",
    description="A combination of 2 hashing algorithms",
    url="https://github.com/yourusername/your_package",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
