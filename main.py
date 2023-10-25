import sys
import os
import math
import concurrent.futures
from multiprocessing import freeze_support
from itertools import repeat
from time import perf_counter, strftime
import csv
import fnmatch
import re
from pathlib import Path
import shutil

import magic                # pip install python-magic-bin
from tqdm import tqdm       # pip install tqdm

# RegEx pattern for BitLocker Recovery Key
pattern = re.compile(r"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}")


# return a list of all files in the target directory
def collect(input_dir):
    FILES = []
    for dirpath, dirnames, filenames in os.walk(input_dir):
        for filename in [f for f in filenames]:
            f = os.path.join(dirpath, filename)
            if os.path.isfile(f):
                FILES.append(f)
                print('%d' % len(FILES), end='\r')
    return FILES


# Calculate Shannon Entropy
# credits: https://www.raedts.biz/forensic-tools/scripts/tc-detective/
def entropy(string):
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy


# main multiprocessed function
# Part 1: Identify BitLocker key files
# Part 2: Identify encrypted containers or disk image files
# 1) filesize divided by 512 = whole number?
# 2) mime-type "application/octet-stream"?
# 3) Entropy value > 7.9 ?
# 4) Check Offsets 510-512 ("00 AA") or 512-519 ("EFI PART")?
def check(f, min_entropy):
        FLAG = None
        entropy_score = 0
        file_size = 0
        try:
            if os.path.isfile(f):
                
                # Part 1
                # Find BitLocker Recovery Key Files
                if fnmatch.fnmatch(f, "*BitLocker Recovery Key*") or fnmatch.fnmatch(f, "*BitLocker-Wiederherstellungsschlüssel*"):
                    return "KEY", f
                
                # Regex search on TXT-Files for key values
                if fnmatch.fnmatch(f, "*.TXT"):
                    # skip files bigger than 10mb
                    if os.path.getsize(f) <= 1048576:   
                        try:
                            # check UTF-16-LE encoded TXT-Files (default used by Microsoft, when saving the recovery key)
                            # this should generate a HIT, if the original recovery key file was renamed...
                            with open(f, "r", encoding="utf-16-le") as text:
                                text = text.read()
                                k = re.findall(pattern, text)
                                if any(k):
                                    return "TXT", f, k
                        
                        except UnicodeDecodeError:                              
                            # check utf-8 encoding (default for notepad on Windows 10)
                            # this should generate a HIT, if the key was saved by the user to a new file
                            try:
                                with open(f, "r", encoding="utf-8") as text:
                                    text = text.read()
                                    k = re.findall(pattern, text)
                                    if any(k):
                                        return "TXT", f, k
                            
                            except UnicodeDecodeError:
                                # skip file, if decoding it in UTF-16-LE or UTF-8 fails
                                return None

                # Part 2
                # Identify encrypted containers or disk image files    
                # Filesize Check: filesize / 512 = whole number?
                if (os.path.getsize(f) / 512).is_integer():
                    # Check mime-type: "application/octet-stream" if VeraCrypt, TrueCrypt, VHD, VHDX
                    MIME = str(magic.from_buffer((open(f, "rb").read(1024)), mime=True))
                    if MIME == "application/octet-stream":
                        with open(f, "rb") as fi:
                            # read the first chunk of 2048 bytes
                            data = fi.read(2048)
                            
                            # calculate shannon entropy
                            entropy_score = entropy(data)
                            if entropy_score > min_entropy:
                                FLAG = "ENTROPY_HIT"

                            # check byte offsets: 512-519 for "EFI PART" or 510-512 for "55 AA" 
                            if data[512:520] == b'EFI PART' or data[510:512] == b'U\xaa':
                                FLAG = "DISKIMG_HIT"
                            
            return FLAG, f, entropy_score
        
        except PermissionError:
            return None
        
        except Exception as e:
            #print("ERROR", e)
            return "ERROR", f, e


# function to write results (list to csv)
def write_csv(lst, output):
    with open(output, 'w', encoding="utf-8", newline='') as f:
            write = csv.writer(f)
            write.writerows(lst)


def main(i, e, cpu):
    t1 = perf_counter()
    # collect files in source, return a list of all files
    print("\nCollecting files...")
    FILES = collect(i)
    
    # multiprocess the main function (for each file in list)
    print("\n\nChecking files...")
    with concurrent.futures.ThreadPoolExecutor(cpu) as executor:
        results = list(tqdm(executor.map(check, FILES, repeat(e)), total=len(FILES)))
    
    # parse and clean results
    results = [x for x in results if x != None]
    KEY_FILES = [x for x in results if x[0] == "KEY"]
    KEY_FILES = [x[1:] for x in KEY_FILES]
    TXT_FILES = [x for x in results if x[0] == "TXT"]
    TXT_FILES = [x[1:] for x in TXT_FILES]
    ENTROPY_HITS = [x for x in results if x[0] == "ENTROPY_HIT"]
    ENTROPY_HITS = [x[1:] for x in ENTROPY_HITS]
    DISKIMG_HITS = [x for x in results if x[0] == "DISKIMG_HIT"]
    DISKIMG_HITS = [x[1:] for x in DISKIMG_HITS]
    ERRORS = [x for x in results if x[0] == "ERROR"]
    ERRORS = [x[1:] for x in ERRORS]
    
    # print results
    t2 = perf_counter()
    print(f"DONE! Runtime: {round((t2 - t1), 2)} [s]")
    print("\n-------------------------------------------------")
    print("BitLocker Key Filename Hits:", len(KEY_FILES))
    print("BitLocker Key Regex Hits:", len(TXT_FILES))
    print("Encryption Check Hits:", len(ENTROPY_HITS))
    print("Disk Image Check Hits:", len(DISKIMG_HITS))
    print("Errors:", len(ERRORS))   
    print("-------------------------------------------------")
    if any(KEY_FILES):
        print("\n\n### BitLocker Key Filename Hits ###")
        for x in KEY_FILES:
            print(x)
    if any(TXT_FILES):
        print("\n\n### BitLocker Key Regex Hits ###")
        for x in TXT_FILES:
            print(x)
    if any(ENTROPY_HITS):
        print("\n\n### Encryption Check Hits ###")
        for x in ENTROPY_HITS:
            print(x)
    if any(DISKIMG_HITS):
        print("\n\n### Disk Image Check Hits ###")
        for x in DISKIMG_HITS:
            print(x)
    print("\n\n-------------------------------------------------")
    
    # log and save results
    timestr = strftime("%Y%m%d%H%M%S_")
    out_path = timestr + "results"
    out_path_key = os.path.join(out_path, "BitLocker_KeyFiles")
    if any(KEY_FILES) or any(TXT_FILES) or any(ENTROPY_HITS) or any(DISKIMG_HITS) or any(ERRORS):
        (Path(out_path)).mkdir(parents=True, exist_ok=True)
    
    if any(KEY_FILES):
        print("Saving Key Files...")
        (Path(f"{out_path}/BitLocker_KeyFiles")).mkdir(parents=True, exist_ok=True)  
        for f in KEY_FILES:
            try:
                shutil.copy(f[0], os.path.join(out_path_key, os.path.basename(f[0])))
            except Exception as e:
                print(e)
                continue
        print(f"Key Files saved to '{os.getcwd()}\{out_path_key}'")
    if any(TXT_FILES):
        write_csv(TXT_FILES, f"{out_path}/BitLocker_regex_key_hits.csv")
        print(f"Results written to '{os.getcwd()}\{out_path}\BitLocker_regex_key_hits.csv'")
    if any(ENTROPY_HITS):
        write_csv(ENTROPY_HITS, f"{out_path}/entropy_hits.csv")
        print(f"Results written to '{os.getcwd()}\{out_path}\entropy_hits.csv'")
    if any(DISKIMG_HITS):
        write_csv(DISKIMG_HITS, f"{out_path}/diskimage_hits.csv")
        print(f"Results written to '{os.getcwd()}\{out_path}\diskimage_hits.csv'")
    if any(ERRORS):
        write_csv(ERRORS, f"{out_path}/errors.csv")
        print(f"Errors written to '{os.getcwd()}\{out_path}\errors.csv'")
    x = input("\nDone! Press any key to quit...")


if __name__ == "__main__":
    freeze_support()
    print("   ____ _  __ _____ ____                               ")
    print("  / __// |/ // ___// __/____ ___ _ ___   ___  ___  ____")
    print(" / _/ /    // /__ _\ \ / __// _ `// _ \ / _ \/ -_)/ __/")
    print("/___//_/|_/ \___//___/ \__/ \_,_//_//_//_//_/\__//_/   ")
    print("")
    print("by Kantonspolizei Uri, Spezialdienste, marco.luperto@ur.ch\n")
    print("Scan drive/directory for:")
    print("- BitLocker recovery key files")
    print("- encrypted files")
    print("- virtual hard disk files\n")    
    
    source_dir = input("Select source ('F:\\'): ")
    if source_dir == "":
        sys.exit("Invalid argument: empty source!")
    if not os.path.isdir(source_dir):
        sys.exit(f"Folder {source_dir} not found!")
    
    e = float(input("Entropy score ['Enter' = default (7.9)]: ") or "7.9")
    if e >= 8 or e <= 0:
        sys.exit(f"Invalid argument: -e {e}. Validation range is between 0.0 and 8.0")
    
    main(source_dir, e, os.cpu_count() - 2)














