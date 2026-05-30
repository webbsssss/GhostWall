from setuptools import setup, find_packages

setup(
    name="ghostwall",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "torch>=2.1.0",
        "transformers>=4.38.0",
        "sentence-transformers>=2.5.0",
        "fastapi>=0.109.0",
        "uvicorn>=0.27.0",
        "numpy>=1.24.0",
        "scikit-learn>=1.3.0",
        "xgboost>=2.0.0",
        "faiss-cpu>=1.7.4",
        "redis>=5.0.0",
        "requests>=2.31.0",
        "pyyaml>=6.0.1",
    ],
    python_requires=">=3.10",
)
