#!/bin/bash

export PATH=$PATH:/home/elliot/.local/share/gem/ruby/3.0.0/bin

if [[ $# == 1 ]]; then
	JEKYLL_ENV=production bundle exec jekyll b -d blog
	$JEKYLL_ENV
	# JEKYLL_ENV=production bundle exec jekyll b -d blog
	cd blog
	git add .
	git commit -m "$1"
	git push -u origin main
else
	echo "Usage: $0 'Git Commit Message'"
fi
