Name: 		rats
Summary: 	Rough Auditing Tool for Security
Version: 	2.1
Release: 	1
Copyright: 	GPL
Group:		Development/Tools
Source0: 	http://www.securesw.com/rats/rats-%{version}.tar.gz
Packager: 	Riku Meskanen <mesrik@cc.jyu.fi>
Vendor: 	Secure Software Solutions
Buildroot: 	/var/tmp/%{name}-root
BuildPrereq: 	expat-devel
Requires: 	expat


%description
RATS scans through code, finding potentially dangerous function calls.
The goal of this tool is not to definitively find bugs (yet). The 
current goal is to provide a reasonable starting point for performing 
manual security audits.

The initial vulnerability database is taken directly from things that
could be easily found when starting with the forthcoming book, 
"Building Secure Software" by Viega and McGraw.  

RATS is released under version 2 of the GNU Public License (GPL).


%prep
%setup 

%build
CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
./configure --prefix=/usr \
	    --datadir=%{_datadir}/rats
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{%{_datadir}/rats,%{_bindir},%{_mandir}/man1}
install -c rats $RPM_BUILD_ROOT/%{_bindir}
install -c -m644 *.xml $RPM_BUILD_ROOT/%{_datadir}/rats
install -c -m644 *.1 $RPM_BUILD_ROOT/%{_mandir}/man1

%post

%preun

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%dir %{_datadir}/rats
%doc README README.win32
%attr(755,root,root) %{_bindir}/*
%{_datadir}/rats/*
%{_mandir}/man1/*

%changelog
* Sat Sep 21 2002 Riku Meskanen <mesrik@cc.jyu.fi>
- Based on the original .spec by guys listed below
- Fixed spec file version number
- Rewrote portions of spec file using proper variables, attr, added %doc etc.

* Mon May 15 2002 Robert M. Zigweid <rzigweid@securesw.com>
- Fixed spec file for 1.5 based changes from Darryl Luff <darryl@snakegully.nu>

* Sat Jun 2 2001 Scott Shinn <scott@securesw.com>
- 1.0 release 

* Mon May 21 2001 Scott Shinn <scott@securesw.com>
- initial release
