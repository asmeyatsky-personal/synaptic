#!/bin/bash
pip install -e .
python -m uvicorn synaptic_bridge.presentation.api.main:app --reload
