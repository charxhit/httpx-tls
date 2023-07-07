from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="httpx-tls",
    version="0.0.1",
    author="Charchit Agarwal",
    author_email="charchit.a00@gmail.com",
    url="https://www.github.com/charxhit/recaptcha-manager",
    description="Almighty patch to expose and configure low-level connection details in httpx",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires='>=3.5',
    packages=['httpx_tls', 'httpx_tls.patch'],
    install_requires=['httpx',
                      'tlslite-ng @ git+https://github.com/charxhit/tlslite-ng.git@httpx-integration',
                      'trio',
                      'user-agents',
                      'h2',
                      'anyio']
)