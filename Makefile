build:
	proxychains4 bundle exec jekyll build
	echo "please add/commit/push->origin/master"
deploy:
	cp -r _site/ /tmp/
	git checkout gh-pages
	rm -r ./*
	cp -r /tmp/_site/* ./
	git add -A
	git commit -m "deploy blog"
	git push -f origin gh-pages
	git checkout master
	echo "deploy successful"
