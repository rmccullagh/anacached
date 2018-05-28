#!/bin/bash

~/bin/anaserver -l 127.0.0.1 -p 8080 --enable-core-dumps --idle-timeout 6000 $@
