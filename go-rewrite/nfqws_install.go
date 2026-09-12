package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// installNfqws — явная, вызываемая руками подкоманда, а НЕ то, что демон
// делает сам при старте с -obfuscate. Сборка стороннего C-проекта из
// исходников и apt install системных пакетов — это system-level действие,
// которое должен осознанно запустить оператор один раз, а не то, что должно
// молча происходить в фоновом сервисе при каждом рестарте/ребуте.
func installNfqws(args []string) {
	if os.Geteuid() != 0 {
		log.Fatalf("нужен root: sudo warpwp-go install-nfqws")
	}
	if p, err := exec.LookPath("nfqws"); err == nil {
		fmt.Println("nfqws уже установлен:", p)
		return
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		log.Fatalf("автоустановка поддерживает только apt (Debian/Ubuntu). " +
			"На другом дистрибутиве собери вручную: https://github.com/bol-van/zapret (каталог nfq, make)")
	}

	tmp, err := os.MkdirTemp("", "warpwp-nfqws-build-")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	steps := []struct {
		desc string
		cmd  *exec.Cmd
	}{
		{"обновляю списки пакетов", exec.Command("apt-get", "update", "-qq")},
		{"ставлю зависимости сборки", exec.Command("apt-get", "install", "-y", "-qq",
			"build-essential", "git", "zlib1g-dev", "libnetfilter-queue-dev", "libnfnetlink-dev", "libmnl-dev", "libcap-dev")},
		{"клонирую zapret (bol-van/zapret)", exec.Command("git", "clone", "--depth", "1",
			"https://github.com/bol-van/zapret.git", tmp+"/zapret")},
	}
	for _, s := range steps {
		log.Printf("install-nfqws: %s...", s.desc)
		s.cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		s.cmd.Stdout = os.Stdout
		s.cmd.Stderr = os.Stderr
		if err := s.cmd.Run(); err != nil {
			log.Fatalf("install-nfqws: %s: %v", s.desc, err)
		}
	}

	log.Printf("install-nfqws: собираю nfqws...")
	build := exec.Command("make")
	build.Dir = tmp + "/zapret/nfq"
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		log.Fatalf("install-nfqws: make: %v", err)
	}

	install := exec.Command("install", "-m", "0755", tmp+"/zapret/nfq/nfqws", "/usr/local/bin/nfqws")
	install.Stdout = os.Stdout
	install.Stderr = os.Stderr
	if err := install.Run(); err != nil {
		log.Fatalf("install-nfqws: install: %v", err)
	}

	fmt.Println("nfqws поставлен: /usr/local/bin/nfqws")
	fmt.Println("Включить обфускацию: warpwp-go serve -obfuscate ...")
}
