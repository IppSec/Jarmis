# In Development.

This was created in two days for a CTF, so the code is very very bad.  Mainly did this to learn FastAPI and highlight some work salesforce did with fingerprinting TLS.  Decided it would be a fun project to turn into a real application, so will be fixing the code overtime.

# Credit
## Sales Force for all their work
* https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a
* https://github.com/salesforce/jarm
## ChristopherGS for his FastAPI Tutorial
* https://christophergs.com/tutorials/ultimate-fastapi-tutorial-pt-1-hello-world/


## Part 1 Local Setup

1. `pip install poetry`
2. Install dependencies `cd` into the directory where the `pyproject.toml` is located then `poetry install`
3. Run the FastAPI server via poetry `poetry run ./run.sh`
4. Open http://localhost:8001/
