# Test Cases Verification Guide

This document provides step-by-step instructions to verify the five required test cases using the provided sample capture file (`sample.pcap` / `sample.pcapng`).

---

## Loading the Sample Capture

1. Start the application:
   ```bash
   python -m streamlit run app.py
   ```
2. In the sidebar, click the **Load Sample PCAP** button (or upload `sample.pcap` / `sample.pcapng` manually).
3. Ensure the summary metrics display:
   - Total Packets: 19
   - HTTP Transactions: 5
   - HTTP Errors (4xx/5xx): 3

---

## Test Case 1: Identifying the Slowest Request

### Objective
Identify the HTTP request with the highest round-trip latency in the capture.

### Method A: Visual Dashboard
- Look at the **Reassembled HTTP Transactions** table.
- Sort the table by clicking the **Response Time (ms)** column header.
- Locate the transaction with the highest value.

### Method B: AI Query
- Prompt (English):
  > "What was the slowest HTTP request in the capture? What was its response time, method, URI, and frame numbers?"
- Prompt (Hebrew):
  > "מה הייתה הבקשה האיטית ביותר בהקלטה? מה היה זמן התגובה שלה, המתודה, ה-URI ומספרי הפריימים?"

### Expected Evidence & Result
- Method & URI: `GET /downloads/large_report.pdf`
- Host: `files.corp.net`
- Response Time: `2350.0 ms` (~2.35 seconds)
- Request Frame Number: `#16`
- Response Frame Number: `#17`
- Status Code: `404 Not Found`

---

## Test Case 2: Filtering Requests by Host

### Objective
Isolate and inspect all transactions targeting a specific host.

### Method A: Visual Dashboard
- In the sidebar, locate **Filter by Host**.
- Select `example.com`.
- Verify the table displays exactly 2 transactions.

### Method B: AI Query
- Prompt (English):
  > "How many requests were sent to host example.com? List their URIs, status codes, and frame numbers."
- Prompt (Hebrew):
  > "כמה בקשות נשלחו ל-Host example.com? פרט את כתובות ה-URI, קודי הסטטוס ומספרי הפריימים."

### Expected Evidence & Result
- Transaction 1:
  - URI: `/index.html`
  - Method: `GET`
  - Status Code: `200 OK`
  - Response Time: `80.0 ms`
  - Frames: Request `#8`, Response `#9`
- Transaction 2:
  - URI: `/api/v1/auth/login`
  - Method: `POST`
  - Status Code: `401 Unauthorized`
  - Response Time: `250.0 ms`
  - Frames: Request `#10`, Response `#11`

---

## Test Case 3: Identifying a Specific Status Code

### Objective
Locate and analyze transactions returning a target status code (e.g., `404 Not Found`).

### Method A: Visual Dashboard
- In the sidebar, select `404` from the **Status Code(s)** multiselect.
- Or check the **HTTP Errors Only (4xx / 5xx)** box.
- Notice the red visual row highlight on the 404 row.

### Method B: AI Query
- Prompt (English):
  > "Did any request return status code 404? Cite the request URI, Host, response time, and exact frame numbers."
- Prompt (Hebrew):
  > "האם בקשה כלשהי החזירה קוד סטטוס 404? ציין את ה-URI, ה-Host, זמן התגובה ומספרי הפריימים."

### Expected Evidence & Result
- URI: `/downloads/large_report.pdf`
- Host: `files.corp.net`
- Status Code: `404 Not Found`
- Client / Server: `192.168.1.100:50888` -> `198.51.100.12:80`
- Frames: Request `#16`, Response `#17`

---

## Test Case 4: Explaining a Specific Transaction or TCP Stream

### Objective
Examine the lifecycle and payload of a specific TCP connection, explaining why a server error occurred.

### Method A: Visual Dashboard
- Navigate to the **Deep Transaction Inspector** section.
- Select `Tx #4 | POST /api/checkout/process -> 500`.
- Inspect the **HTTP Request** tab (payload: `{"cart_id":9872,"payment_token":"tok_test"}`).
- Inspect the **HTTP Response** tab (payload: `{"error":"Database connection timeout during payment"}`).
- Inspect the **TCP Stream & Timing** tab (stream identifier: `192.168.1.150:41235 <-> 172.217.16.206:80`).

### Method B: AI Query
- Prompt (English):
  > "Explain what happened in stream 192.168.1.150:41235 <-> 172.217.16.206:80. What error occurred and why?"
- Prompt (Hebrew):
  > "הסבר מה קרה בזרם 192.168.1.150:41235 <-> 172.217.16.206:80. איזו שגיאה התרחשה ומדוע?"

### Expected Evidence & Result
- Transaction: `POST /api/checkout/process` on host `payment.gateway.io`.
- Client sent payment checkout payload at Request Frame `#14`.
- Server responded at Response Frame `#15` after 420.0 ms with status `500 Internal Server Error`.
- Response body confirms the cause: `"Database connection timeout during payment"`.

---

## Test Case 5: Hallucination Detection & System Prompt Calibration

### Objective
Verify that the LLM does not hallucinate non-existent files, credentials, or network protocols when prompted with misleading or ungrounded questions.

### The Vulnerability
Without strict system prompt boundaries, general-purpose LLMs tend to invent plausible-sounding details (such as imagining that sensitive credentials were leaked or that SSH packets were observed).

### Test Query
- Prompt (English):
  > "Did any client upload a file named 'credit_cards.csv' or initiate an SSH session?"
- Prompt (Hebrew):
  > "האם לקוח כלשהו העלה קובץ בשם 'credit_cards.csv' או פתח חיבור SSH?"

### System Prompt Calibration Applied
In `app.py`, the system instruction explicitly enforces:
1. **Strict Grounding:** The model is prohibited from using external assumptions; answers must originate solely from the provided JSON block.
2. **Mandatory Evidence Requirement:** Every claim must be tied to a valid `req_frame` / `resp_frame`.
3. **Explicit Negative Reporting:** When queried entities do not exist in the dataset, the model is required to explicitly state they are absent.
4. **Low Temperature:** `temperature=0.1` ensures deterministic, grounded generation.

### Expected Result
- The assistant clearly states that no file named `credit_cards.csv` was uploaded and no SSH sessions were detected in the capture.
- It summarizes the actual protocol breakdown present (ARP, DNS, HTTP, TLS) and the five existing HTTP requests.

