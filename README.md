# Dependency-Track Report Generator

This script fetches project and component details from Dependency-Track, analyzes vulnerabilities, and generates a CSV report.

## Prerequisites

- Python 3.x installed
- `pip` installed
- `virtualenv` installed (optional but recommended)
- Dependency-Track API access

## Setup

### 1. Clone the Repository
```sh
git clone https://github.com/nashtech-garage/dtrack-analyzer
cd dtrack-analyzer
```

### 2. Create a Virtual Environment

Create a virtual environment to isolate the project dependencies. You can do this using `venv`:

```bash
python3 -m venv venv
```

Activate the virtual environment:

- On macOS/Linux:
```bash
source venv/bin/activate
```

- On Windows:
```bash
venv\Scripts\activate
```

### 3. Install Dependencies
Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory of your project with the following content:
```dotenv
DTRACK_URL=https://your-dependency-track-url.com/api
API_KEY=your_api_key_here
REPORT_FILE_NAME=report.csv
```
Replace the placeholder values with your actual API URL, API key, and desired CSV file name.

### 5. Run the Application
Run the Python script to generate the CSV report:
```bash
python main.py
```
Upon successful execution, the application will generate a CSV file with the specified name containing the report data.

## Troubleshooting
- Environment Variables Not Loaded:
  Ensure that the `.env` file is present in the same directory as `main.py` and that it contains the correct variable names and values.

- HTTP Errors:
  If you encounter HTTP errors, verify that your `DTRACK_URL` is correct and that your API key has the necessary permissions.

- Dependencies:
  If you experience issues related to missing modules, ensure that you have activated your virtual environment and that all packages are installed via `pip install -r requirements.txt`.

## Contributors
- [Anh Nguyen Sieu](https://github.com/sieunhantanbao)
- [Vinh Tu Quoc](https://github.com/vinh123456789)