package egovframework.com.msa.manager;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MsaShortcutController {

    @GetMapping({"/msa", "/msa/"})
    public String msaShortcut() {
        return "redirect:/admin/msa/manager";
    }
}
