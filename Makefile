PYTHON ?= python

run:
	$(PYTHON) -m streamlit run app.py

test:
	$(PYTHON) -m pytest -q tests/test_ground_truth.py

test-all:
	$(PYTHON) -m pytest -q

cache-warm:
	$(PYTHON) -c "import pipeline; print(pipeline.run_scan('fixtures/ground_truth_repo')['ok'])"

demo:
	$(PYTHON) -m streamlit run app.py
