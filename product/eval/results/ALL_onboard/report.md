# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 66 pcaps | 6,801 windows | 21.6 host-hours | 43 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 24 | 43 | 3.4 | 0.1145 | 0.0 | 0.0464 |
| binary | 24 | 43 | 3.4 | 0.0588 | 0.0186 | 0.0464 |

Detected 24/43 runs, median time to detect 3.4 s (from the attack's real start), false alarm episodes 0.0464 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 15 | 11 | [45, 92] | 11 | 3.8 | 3.8 | 0.765 |
| novel | 28 | 13 | [28, 66] | 13 | 3.1 | 3.1 | 0.885 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 5 | 4 | [28, 99] | 4 | 6.65 | 6.65 | 1.0 |
| assoc_flood | 5 | 0 | [0, 52] | 0 |  |  |  |
| exfiltration | 8 | 2 | [3, 65] | 2 | 15.5 | 15.5 | 0.972 |
| malformed_pdu | 6 | 2 | [4, 78] | 2 | 10.4 | 10.4 | 0.043 |
| preamble_polyglot | 7 | 7 | [59, 100] | 7 | 0.5 | 0.5 | 0.996 |
| ransomware_like | 4 | 4 | [40, 100] | 4 | 5.35 | 5.35 | 0.736 |
| recon | 8 | 5 | [24, 91] | 5 | 3.7 | 3.7 | 0.794 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 2 | 2 | [16, 100] | 2 | 64.05 | 64.05 | 1.0 |
| ae_bruteforce/find_guess (novel) | 3 | 2 | [9, 99] | 2 | 3.4 | 3.4 | 1.0 |
| assoc_flood/echo_storm (novel) | 3 | 0 | [0, 71] | 0 |  |  |  |
| assoc_flood/hold_full_rq | 2 | 0 | [0, 84] | 0 |  |  |  |
| exfiltration/drip (novel) | 3 | 1 | [1, 91] | 1 | 27.2 | 27.2 | 1.0 |
| exfiltration/find_get | 2 | 1 | [1, 99] | 1 | 3.8 | 3.8 | 0.944 |
| exfiltration/move_to_self (novel) | 3 | 0 | [0, 71] | 0 |  |  |  |
| malformed_pdu/assoc_fuzz | 3 | 2 | [9, 99] | 2 | 10.4 | 10.4 | 0.043 |
| malformed_pdu/pdata_fuzz (novel) | 3 | 0 | [0, 71] | 0 |  |  |  |
| preamble_polyglot/rest_elf (novel) | 2 | 2 | [16, 100] | 2 | 0.75 | 0.75 | 1.0 |
| preamble_polyglot/rest_mz | 2 | 2 | [16, 100] | 2 | 0.65 | 0.65 | 0.985 |
| preamble_polyglot/stow_mz (novel) | 3 | 3 | [29, 100] | 3 | 0.5 | 0.5 | 1.0 |
| ransomware_like/get_restore | 2 | 2 | [16, 100] | 2 | 13.05 | 13.05 | 0.724 |
| ransomware_like/get_restore_delete (novel) | 2 | 2 | [16, 100] | 2 | 5.35 | 5.35 | 0.75 |
| recon/dicom_ping (novel) | 3 | 1 | [1, 91] | 1 | 4.5 | 4.5 | 0.0 |
| recon/nmap_connect | 2 | 2 | [16, 100] | 2 | 3.5 | 3.5 | 0.984 |
| recon/nmap_syn (novel) | 3 | 2 | [9, 99] | 2 | 3.55 | 3.55 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 16 | 9 | [30, 80] | 9 | 3.8 | 3.8 | 0.729 |
| low | 14 | 9 | [35, 87] | 9 | 4.0 | 4.0 | 0.862 |
| slow | 13 | 6 | [19, 75] | 6 | 2.7 | 2.7 | 0.932 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 9 | 4 | [14, 79] | 4 | 10.8 | 10.8 | 0.477 |
| unknown | 22 | 17 | [55, 92] | 17 | 3.3 | 3.3 | 0.883 |
| workstation | 12 | 3 | [5, 57] | 3 | 0.5 | 0.5 | 1.0 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 297 | 0.1178 | 7 | 3 |
| 172.28.1.32 | modality | 170 | 0.0706 | 3 | 2 |
| 172.28.1.33 | modality | 304 | 0.3618 | 0 | 0 |
| 172.28.1.34 | modality | 358 | 0.148 | 2 | 3 |
| 172.28.1.35 | modality | 223 | 0.4574 | 0 | 0 |
| 172.28.1.51 | workstation | 715 | 0.5259 | 0 | 4 |
| 172.28.1.52 | workstation | 574 | 0.1707 | 0 | 0 |
| 172.28.1.60 | monitoring | 705 | 0.0 | 0 | 0 |

10 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
