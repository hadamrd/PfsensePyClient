from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pfsense-api-client",
    version="0.1.0",
    author="khalid.majdoub",
    author_email="majdoub.khalid@gmail.com",
    description="A Python client for interacting with the pfSense web interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hadamrd/pfsense-api-client",
    py_modules=['PfsenseAPI', 'Logger'], 
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "beautifulsoup4>=4.12.0"
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pylint>=2.17.0",
            "black>=22.0.0",
        ],
    }
)
