import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core_mesh.business_execution.enterprise_risk_register import EnterpriseRiskRegister

class TestEnterpriseRiskRegister(unittest.TestCase):
    def setUp(self):
        self.register = EnterpriseRiskRegister(company_annual_turnover=20_000_000.0)

    def test_add_risk_inherent_and_residual_scoring(self):
        risk = self.register.add_risk(
            risk_id="RSK-001",
            title="Ransomware Exfiltration via Phishing",
            category="Cybersecurity",
            likelihood=5,
            impact=5,
            existing_controls=["EDR", "Email Gateway", "FIDO2 MFA"],
            control_efficacy=0.60,
            financial_params={"aro": 0.2, "sle": 500_000.0}
        )
        self.assertEqual(risk["inherent_score"], 25)
        self.assertEqual(risk["inherent_severity"], "CRITICAL")
        self.assertEqual(risk["residual_score"], 10.0)
        self.assertEqual(risk["residual_severity"], "MEDIUM")

        # FAIR financial checks
        # ale = 0.2 * 500,000 * (1.0 - (0.6 * 0.7)) = 100,000 * 0.58 = 58,000.0
        self.assertEqual(risk["fair_metrics"]["ale"], 58000.0)
        # mpl = 500,000 / 20,000,000 * 100 = 2.5%
        self.assertEqual(risk["fair_metrics"]["maximum_probable_loss_percentage"], 2.5)

    def test_treatment_plan_and_sla_states(self):
        self.register.add_risk(
            risk_id="RSK-002",
            title="Supply Chain Disruption (Tier 1 Cloud)",
            category="Operational",
            likelihood=3,
            impact=4,
            control_efficacy=0.30
        )
        # Invalid strategy raises ValueError
        with self.assertRaises(ValueError):
            self.register.set_treatment_plan("RSK-002", "InvalidStrategy", "John Doe", 6.0, 30)

        # Valid strategy
        plan = self.register.set_treatment_plan("RSK-002", "Mitigate", "Jane Smith", 4.0, sla_days=30)
        self.assertEqual(plan["strategy"], "Mitigate")
        self.assertEqual(plan["owner"], "Jane Smith")

        # Check status: current time
        st_now = self.register.get_risk_status("RSK-002")
        self.assertEqual(st_now["sla_status"], "ON_TRACK")
        self.assertGreater(st_now["days_remaining"], 20.0)

        # Check status: simulated warning (25 days later, 5 days left)
        future_warn = plan["assigned_at"] + (25 * 86400)
        st_warn = self.register.get_risk_status("RSK-002", current_time=future_warn)
        self.assertEqual(st_warn["sla_status"], "WARNING")

        # Check status: simulated overdue (35 days later, overdue)
        future_overdue = plan["assigned_at"] + (35 * 86400)
        st_overdue = self.register.get_risk_status("RSK-002", current_time=future_overdue)
        self.assertEqual(st_overdue["sla_status"], "OVERDUE")
        self.assertLess(st_overdue["days_remaining"], 0)

    def test_risk_matrix_summary(self):
        self.register.add_risk("R1", "Risk 1", "Cyber", 5, 5, control_efficacy=0.8, financial_params={"aro": 1.0, "sle": 100_000.0})
        self.register.add_risk("R2", "Risk 2", "Legal", 2, 2, control_efficacy=0.0, financial_params={"aro": 0.1, "sle": 20_000.0})

        summary = self.register.get_risk_matrix_summary()
        self.assertEqual(summary["total_risks"], 2)
        self.assertEqual(summary["inherent_distribution"]["CRITICAL"], 1)
        self.assertEqual(summary["inherent_distribution"]["LOW"], 1)
        # Residual distribution: R1 had inherent 25 * 0.2 = 5 (LOW), R2 has inherent 4 (LOW)
        self.assertEqual(summary["residual_distribution"]["LOW"], 2)
        self.assertGreater(summary["total_annualized_loss_expectancy_eur"], 0.0)
        self.assertGreater(summary["aggregate_mitigation_rate_percentage"], 50.0)

if __name__ == "__main__":
    unittest.main()
