#!/usr/bin/env python3

from multiprocessing import Pool
import os
import subprocess

src = "/home/USERNAME/data/prod"
dirs = next(os.walk(src))[1]

def backingup(dirs):
 dest = "/home/USERNAME/data/prod_backup"
 subprocess.call(["rsync", "-arq", src+'/'+ dirs, dest])

p = Pool(len(dirs))
p.map(backingup, dirs)