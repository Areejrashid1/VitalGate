# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 66 pcaps | 6,801 windows | 26.4 host-hours | 43 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 36 | 43 | 3.4 | 1.1317 | 0.0 | 1.6672 |
| binary | 36 | 43 | 3.4 | 0.9081 | 0.2122 | 2.3871 |

Detected 36/43 runs, median time to detect 3.4 s (from the attack's real start), false alarm episodes 3.0692 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 15 | 13 | [60, 98] | 13 | 3.7 | 3.7 | 0.733 |
| novel | 28 | 23 | [63, 94] | 23 | 3.3 | 3.3 | 0.705 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 5 | 5 | [48, 100] | 5 | 3.5 | 3.5 | 0.979 |
| assoc_flood | 5 | 1 | [1, 72] | 1 | 0.7 | 0.7 | 0.0 |
| exfiltration | 8 | 7 | [47, 100] | 7 | 9.6 | 9.6 | 0.939 |
| malformed_pdu | 6 | 4 | [22, 96] | 4 | 3.8 | 3.8 | 0.054 |
| preamble_polyglot | 7 | 7 | [59, 100] | 7 | 0.5 | 0.5 | 0.861 |
| ransomware_like | 4 | 4 | [40, 100] | 4 | 3.45 | 3.45 | 0.732 |
| recon | 8 | 8 | [63, 100] | 8 | 3.45 | 3.45 | 0.639 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 2 | 2 | [16, 100] | 2 | 4.05 | 4.05 | 1.0 |
| ae_bruteforce/find_guess (novel) | 3 | 3 | [29, 100] | 3 | 3.3 | 3.3 | 0.966 |
| assoc_flood/echo_storm (novel) | 3 | 1 | [1, 91] | 1 | 0.7 | 0.7 | 0.0 |
| assoc_flood/hold_full_rq | 2 | 0 | [0, 84] | 0 |  |  |  |
| exfiltration/drip (novel) | 3 | 2 | [9, 99] | 2 | 16.0 | 16.0 | 0.978 |
| exfiltration/find_get | 2 | 2 | [16, 100] | 2 | 2.3 | 2.3 | 0.972 |
| exfiltration/move_to_self (novel) | 3 | 3 | [29, 100] | 3 | 46.1 | 46.1 | 0.891 |
| malformed_pdu/assoc_fuzz | 3 | 3 | [29, 100] | 3 | 3.8 | 3.8 | 0.072 |
| malformed_pdu/pdata_fuzz (novel) | 3 | 1 | [1, 91] | 1 | 93.6 | 93.6 | 0.0 |
| preamble_polyglot/rest_elf (novel) | 2 | 2 | [16, 100] | 2 | 0.75 | 0.75 | 0.746 |
| preamble_polyglot/rest_mz | 2 | 2 | [16, 100] | 2 | 0.65 | 0.65 | 0.985 |
| preamble_polyglot/stow_mz (novel) | 3 | 3 | [29, 100] | 3 | 0.5 | 0.5 | 0.855 |
| ransomware_like/get_restore | 2 | 2 | [16, 100] | 2 | 3.05 | 3.05 | 0.715 |
| ransomware_like/get_restore_delete (novel) | 2 | 2 | [16, 100] | 2 | 5.35 | 5.35 | 0.75 |
| recon/dicom_ping (novel) | 3 | 3 | [29, 100] | 3 | 3.6 | 3.6 | 0.047 |
| recon/nmap_connect | 2 | 2 | [16, 100] | 2 | 3.5 | 3.5 | 0.984 |
| recon/nmap_syn (novel) | 3 | 3 | [29, 100] | 3 | 3.1 | 3.1 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 16 | 14 | [62, 98] | 14 | 2.95 | 2.95 | 0.679 |
| low | 14 | 12 | [57, 98] | 12 | 3.8 | 3.8 | 0.732 |
| slow | 13 | 10 | [46, 95] | 10 | 3.3 | 3.3 | 0.746 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 9 | 7 | [40, 97] | 7 | 3.8 | 3.8 | 0.289 |
| unknown | 22 | 17 | [55, 92] | 17 | 3.3 | 3.3 | 0.883 |
| workstation | 12 | 12 | [74, 100] | 12 | 1.9 | 1.5 | 0.727 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 371 | 0.1402 | 10 | 3 |
| 172.28.1.32 | modality | 237 | 0.0675 | 3 | 2 |
| 172.28.1.33 | modality | 389 | 0.3728 | 38 | 3 |
| 172.28.1.34 | modality | 472 | 0.1568 | 35 | 3 |
| 172.28.1.35 | modality | 264 | 0.4773 | 44 | 3 |
| 172.28.1.51 | workstation | 850 | 0.5071 | 419 | 4 |
| 172.28.1.52 | workstation | 848 | 0.1922 | 32 | 4 |
| 172.28.1.60 | monitoring | 890 | 0.0022 | 0 | 0 |

16 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
