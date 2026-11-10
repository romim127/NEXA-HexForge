"""CLI educativa A4: entropía por sección PE."""
import argparse
import json
from .entropy_academy import inspect_section_entropy

def main():
    parser=argparse.ArgumentParser(description="NEXA Hex Academy A4 — Entropy Lab")
    parser.add_argument("file")
    parser.add_argument("--section",type=int,default=0)
    args=parser.parse_args()
    print(json.dumps(inspect_section_entropy(args.file,args.section),ensure_ascii=False,indent=2))

if __name__=="__main__":main()
