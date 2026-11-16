# VitalGate test-bed evaluation

Frozen bundle 2026-11-16 17:38:40 | 59 pcaps | 4,795 windows | 8.3 host-hours | 17 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 16 | 17 | 4.5 | 0.4483 | 0.0 | 0.4803 |
| binary | 16 | 17 | 4.5 | 0.2562 | 0.1841 | 0.4803 |

Detected 16/17 runs, median time to detect 4.45 s (from the attack's real start), false alarm episodes 0.4803 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 7 | 7 | [59, 100] | 7 | 3.5 | 3.5 | 0.826 |
| novel | 10 | 9 | [55, 100] | 9 | 5.7 | 5.7 | 0.973 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 2 | 2 | [16, 100] | 2 | 2.75 | 2.75 | 1.0 |
| assoc_flood | 2 | 2 | [16, 100] | 2 | 72.85000000000001 | 72.85000000000001 | 0.676 |
| exfiltration | 3 | 2 | [9, 99] | 2 | 10.600000000000001 | 10.600000000000001 | 0.863 |
| malformed_pdu | 2 | 2 | [16, 100] | 2 | 5.0 | 5.0 | 0.881 |
| preamble_polyglot | 3 | 3 | [29, 100] | 3 | 1.7 | 1.7 | 0.993 |
| ransomware_like | 2 | 2 | [16, 100] | 2 | 5.550000000000001 | 5.550000000000001 | 0.859 |
| recon | 3 | 3 | [29, 100] | 3 | 2.9 | 2.9 | 1.0 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 3.3 | 3.3 | 1.0 |
| ae_bruteforce/find_guess (novel) | 1 | 1 | [2, 100] | 1 | 2.2 | 2.2 | 1.0 |
| assoc_flood/echo_storm (novel) | 1 | 1 | [2, 100] | 1 | 5.9 | 5.9 | 0.935 |
| assoc_flood/hold_full_rq | 1 | 1 | [2, 100] | 1 | 139.8 | 139.8 | 0.417 |
| exfiltration/drip (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 8.9 | 8.9 | 0.727 |
| exfiltration/move_to_self (novel) | 1 | 1 | [2, 100] | 1 | 12.3 | 12.3 | 1.0 |
| malformed_pdu/assoc_fuzz | 1 | 1 | [2, 100] | 1 | 3.5 | 3.5 | 0.762 |
| malformed_pdu/pdata_fuzz (novel) | 1 | 1 | [2, 100] | 1 | 6.5 | 6.5 | 1.0 |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 0.1 | 0.1 | 1.0 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 1.8 | 1.8 | 0.98 |
| preamble_polyglot/stow_mz (novel) | 1 | 1 | [2, 100] | 1 | 1.7 | 1.7 | 1.0 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 5.4 | 5.4 | 0.899 |
| ransomware_like/get_restore_delete (novel) | 1 | 1 | [2, 100] | 1 | 5.7 | 5.7 | 0.818 |
| recon/dicom_ping (novel) | 1 | 1 | [2, 100] | 1 | 8.8 | 8.8 | 1.0 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 2.6 | 2.6 | 1.0 |
| recon/nmap_syn (novel) | 1 | 1 | [2, 100] | 1 | 2.9 | 2.9 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 6 | 6 | [54, 100] | 6 | 3.0999999999999996 | 3.0999999999999996 | 0.934 |
| low | 5 | 4 | [28, 99] | 4 | 4.15 | 4.15 | 0.955 |
| slow | 6 | 6 | [54, 100] | 6 | 7.3500000000000005 | 7.3500000000000005 | 0.852 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 4 | 3 | [19, 99] | 3 | 2.6 | 2.6 | 1.0 |
| unknown | 8 | 8 | [63, 100] | 8 | 3.4 | 3.4 | 0.921 |
| workstation | 5 | 5 | [48, 100] | 5 | 5.9 | 5.9 | 0.834 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 158 | 0.0253 | 29 | 3 |
| 172.28.1.32 | modality | 103 | 0.0291 | 0 | 0 |
| 172.28.1.33 | modality | 117 | 0.0342 | 3 | 3 |
| 172.28.1.34 | modality | 109 | 0.0 | 0 | 2 |
| 172.28.1.35 | modality | 85 | 0.0 | 1 | 3 |
| 172.28.1.51 | workstation | 281 | 0.0819 | 3 | 4 |
| 172.28.1.52 | workstation | 240 | 0.1542 | 2 | 4 |
| 172.28.1.60 | monitoring | 270 | 0.0 | 0 | 0 |

3 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
