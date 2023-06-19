from setuptools import setup, find_packages, find_namespace_packages



with open("requirements.txt") as f:
    install_reqs = f.read().strip().split("\n")

# Filter out comments/hashes
reqs = []
for req in install_reqs:
    if req.startswith("#") or req.startswith("    --hash="):
        continue
    reqs.append(str(req).rstrip(" \\"))


with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name="bitcoin_p2p",
    version="0.3.3",
    author="Andreas Griffin",
    author_email="andreasgriffin@proton.me",
    description="Bitcoin p2p communication tools in python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/andreasgriffin/bitcoin-p2p",
    packages=find_namespace_packages("bitcoin_p2p", include=["bitcoin_p2p.*"]),
    package_dir={"": "bitcoin_p2p"},
    install_requires=reqs,
    classifiers=[
        "Development Status :: 3 - Alpha",  # Replace with the appropriate development status
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.7,<4.0",
)
