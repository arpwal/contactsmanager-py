from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="contactsmanager",
    version="0.1.0",
    author="Arpit Agarwal",
    author_email="arpit@example.com",  # Please update this
    description="Python SDK for ContactsManager API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/arpwal/contactsmanager-py",
    package_dir={"": "contactsmanager"},
    packages=find_packages(where="contactsmanager"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=[
        "PyJWT>=2.0.0",
    ],
) 