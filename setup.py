from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="httpx-tls",
    version="0.0.2-beta.7",
    author="Charchit Agarwal",
    author_email="charchit.a00@gmail.com",
    url="https://github.com/AnCry1596/httpx-tls/",
    description="Almighty patch to expose and configure low-level connection details in httpx",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires='>=3.5',
    packages=['httpx_tls', 'httpx_tls.patch'],
    install_requires=['httpx',
                      'tlslite-ng @ git+https://github.com/AnCry1596/tlslite-ng.git',
                      'trio',
                      'h2',
                      'anyio']
)