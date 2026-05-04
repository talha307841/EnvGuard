from setuptools import setup, find_packages

setup(
    name="envguard",
    version="1.0.0",
    description="Protect .env files from being sent to LLMs by coding agents",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="EnvGuard",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "click>=8.1.7",
        "watchdog>=4.0.0",
        "psutil>=5.9.8",
    ],
    entry_points={
        "console_scripts": [
            "envguard=envguard.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
)
