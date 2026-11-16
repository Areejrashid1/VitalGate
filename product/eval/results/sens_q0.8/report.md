# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 66 pcaps | 6,801 windows | 21.6 host-hours | 43 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 36 | 43 | 3.6 | 0.464 | 0.0 | 0.6032 |
| binary | 36 | 43 | 3.8 | 0.3232 | 0.099 | 0.696 |

Detected 35/43 runs, median time to detect 3.8 s (from the attack's real start), false alarm episodes 0.9744 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 15 | 13 | [60, 98] | 13 | 3.7 | 3.7 | 0.733 |
| novel | 28 | 22 | [59, 92] | 23 | 6.05 | 3.5 | 0.742 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 5 | 5 | [48, 100] | 5 | 3.8 | 3.5 | 0.986 |
| assoc_flood | 5 | 0 | [0, 52] | 1 |  | 0.7 |  |
| exfiltration | 8 | 7 | [47, 100] | 7 | 27.2 | 27.2 | 0.945 |
| malformed_pdu | 6 | 4 | [22, 96] | 4 | 5.8 | 5.8 | 0.056 |
| preamble_polyglot | 7 | 7 | [59, 100] | 7 | 0.5 | 0.5 | 0.884 |
| ransomware_like | 4 | 4 | [40, 100] | 4 | 3.45 | 3.45 | 0.732 |
| recon | 8 | 8 | [63, 100] | 8 | 4.25 | 3.85 | 0.621 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 2 | 2 | [16, 100] | 2 | 7.050000000000001 | 7.050000000000001 | 1.0 |
| ae_bruteforce/find_guess (novel) | 3 | 3 | [29, 100] | 3 | 3.5 | 3.3 | 0.976 |
| assoc_flood/echo_storm (novel) | 3 | 0 | [0, 71] | 1 |  | 0.7 |  |
| assoc_flood/hold_full_rq | 2 | 0 | [0, 84] | 0 |  |  |  |
| exfiltration/drip (novel) | 3 | 2 | [9, 99] | 2 | 39.0 | 39.0 | 1.0 |
| exfiltration/find_get | 2 | 2 | [16, 100] | 2 | 2.3 | 2.3 | 0.972 |
| exfiltration/move_to_self (novel) | 3 | 3 | [29, 100] | 3 | 46.1 | 46.1 | 0.891 |
| malformed_pdu/assoc_fuzz | 3 | 3 | [29, 100] | 3 | 3.8 | 3.8 | 0.074 |
| malformed_pdu/pdata_fuzz (novel) | 3 | 1 | [1, 91] | 1 | 93.6 | 93.6 | 0.0 |
| preamble_polyglot/rest_elf (novel) | 2 | 2 | [16, 100] | 2 | 0.75 | 0.75 | 0.793 |
| preamble_polyglot/rest_mz | 2 | 2 | [16, 100] | 2 | 0.65 | 0.65 | 0.985 |
| preamble_polyglot/stow_mz (novel) | 3 | 3 | [29, 100] | 3 | 0.5 | 0.5 | 0.876 |
| ransomware_like/get_restore | 2 | 2 | [16, 100] | 2 | 3.05 | 3.05 | 0.715 |
| ransomware_like/get_restore_delete (novel) | 2 | 2 | [16, 100] | 2 | 5.35 | 5.35 | 0.75 |
| recon/dicom_ping (novel) | 3 | 3 | [29, 100] | 3 | 7.6 | 7.6 | 0.0 |
| recon/nmap_connect | 2 | 2 | [16, 100] | 2 | 3.5 | 3.5 | 0.984 |
| recon/nmap_syn (novel) | 3 | 3 | [29, 100] | 3 | 4.0 | 3.1 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 16 | 13 | [54, 96] | 14 | 3.8 | 2.95 | 0.734 |
| low | 14 | 12 | [57, 98] | 12 | 3.9 | 3.8 | 0.736 |
| slow | 13 | 10 | [46, 95] | 10 | 3.5 | 3.5 | 0.748 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 9 | 7 | [40, 97] | 7 | 4.0 | 4.0 | 0.29 |
| unknown | 22 | 17 | [55, 92] | 17 | 3.3 | 3.3 | 0.883 |
| workstation | 12 | 11 | [62, 100] | 12 | 10.3 | 5.55 | 0.802 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 297 | 0.1178 | 7 | 3 |
| 172.28.1.32 | modality | 170 | 0.0706 | 3 | 2 |
| 172.28.1.33 | modality | 304 | 0.3618 | 17 | 3 |
| 172.28.1.34 | modality | 358 | 0.148 | 17 | 3 |
| 172.28.1.35 | modality | 223 | 0.4574 | 0 | 0 |
| 172.28.1.51 | workstation | 715 | 0.5259 | 60 | 4 |
| 172.28.1.52 | workstation | 574 | 0.1707 | 26 | 4 |
| 172.28.1.60 | monitoring | 705 | 0.0 | 0 | 0 |

14 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
