# Demo Scenario

## Selected Scenario

**UNSW-NB15 temporal research episode** is the strongest currently runnable demo because the active model was trained on UNSW and the dataset provides timestamps. Exact episode selection and evaluation are documented in `unsw_forecast_expanded_evaluation.json`.

The preferred Friday afternoon PortScan scenario is not selected: its CIC flow CSV has no event timestamps and no PCAP is present.

## Demo Flow

1. Use verified timestamped UNSW flow states.
2. Validate the 46-feature state contract.
3. Run the protected NumPy LSTM.
4. Display current state, recursive T+1 through T+5, contextual progression, ATT&CK context, explanation, abstention, and limitations.

## Limitations

This is a research prototype with one eligible mixed-state future episode, no packet observations, uncalibrated probabilities, and no production deployment claim.
