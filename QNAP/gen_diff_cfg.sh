#!/bin/bash
mv $1 $1.org
diff x86_64.cfg $1.org | grep '^>' | sed 's/^>\ //' > $1
