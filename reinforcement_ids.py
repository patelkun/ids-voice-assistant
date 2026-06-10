import numpy as np
import pandas as pd
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO, DQN
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.callbacks import EvalCallback
import pickle
import warnings
warnings.filterwarnings('ignore')

print("Reinforcement Learning IDS — AI khud seekhega!")
print("=" * 60)

# ============================================
# 1. CUSTOM NETWORK ENVIRONMENT BANAO
# ============================================
class NetworkSecurityEnv(gym.Env):
    """
    Custom RL Environment for Network Security
    Agent — IDS system
    State — network traffic features
    Action — 0=Allow, 1=Block, 2=Alert, 3=Investigate
    Reward — sahi decision pe +10, galat pe -5
    """
    
    def __init__(self):
        super().__init__()
        
        # 8 network features
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(8,), dtype=np.float32
        )
        
        # 4 actions: Allow, Block, Alert, Investigate
        self.action_space = spaces.Discrete(4)
        
        self.action_names = ["Allow", "Block", "Alert", "Investigate"]
        
        # Traffic scenarios
        self.scenarios = self._generate_scenarios()
        self.current_step = 0
        self.max_steps = 1000
        self.total_reward = 0
        
    def _generate_scenarios(self):
        scenarios = []
        
        # Normal traffic — correct action: Allow (0)
        for _ in range(500):
            scenarios.append({
                "features": np.array([
                    np.random.uniform(0, 0.1),   # packet_count (low)
                    np.random.uniform(0.3, 0.7),  # avg_size (medium)
                    np.random.uniform(0, 1),       # port_443
                    0,                             # port_22 (not SSH)
                    np.random.uniform(0, 1),       # port_80
                    np.random.uniform(0, 0.2),     # udp_ratio (low)
                    np.random.uniform(0.3, 1),     # inter_arrival (slow)
                    np.random.uniform(0, 0.1),     # burst_size (low)
                ], dtype=np.float32),
                "correct_action": 0,  # Allow
                "label": "normal"
            })
        
        # SSH Brute Force — correct action: Block (1)
        for _ in range(300):
            scenarios.append({
                "features": np.array([
                    np.random.uniform(0.3, 0.7),  # packet_count (high)
                    np.random.uniform(0.2, 0.4),  # avg_size
                    0,                             # port_443
                    1,                             # port_22 (SSH!)
                    0,                             # port_80
                    0,                             # udp_ratio
                    np.random.uniform(0, 0.1),    # inter_arrival (fast)
                    np.random.uniform(0.3, 0.7),  # burst_size
                ], dtype=np.float32),
                "correct_action": 1,  # Block
                "label": "ssh_brute"
            })
        
        # Ping Flood — correct action: Block (1)
        for _ in range(300):
            scenarios.append({
                "features": np.array([
                    np.random.uniform(0.7, 1.0),  # packet_count (very high)
                    np.random.uniform(0.3, 0.5),  # avg_size
                    0, 0, 0,                       # ports
                    np.random.uniform(0.7, 1.0),  # udp_ratio (high!)
                    np.random.uniform(0, 0.05),   # inter_arrival (very fast)
                    np.random.uniform(0.7, 1.0),  # burst_size (very high)
                ], dtype=np.float32),
                "correct_action": 1,  # Block
                "label": "ping_flood"
            })
        
        # Suspicious — correct action: Alert (2)
        for _ in range(200):
            scenarios.append({
                "features": np.array([
                    np.random.uniform(0.1, 0.3),
                    np.random.uniform(0.5, 0.9),
                    np.random.uniform(0, 1),
                    np.random.uniform(0, 0.5),
                    np.random.uniform(0, 1),
                    np.random.uniform(0.2, 0.5),
                    np.random.uniform(0.1, 0.3),
                    np.random.uniform(0.1, 0.3),
                ], dtype=np.float32),
                "correct_action": 2,  # Alert
                "label": "suspicious"
            })
        
        # Unknown — correct action: Investigate (3)
        for _ in range(200):
            scenarios.append({
                "features": np.array([
                    np.random.uniform(0.2, 0.6),
                    np.random.uniform(0.6, 1.0),
                    np.random.uniform(0, 1),
                    np.random.uniform(0, 1),
                    np.random.uniform(0, 1),
                    np.random.uniform(0.3, 0.6),
                    np.random.uniform(0.05, 0.2),
                    np.random.uniform(0.2, 0.5),
                ], dtype=np.float32),
                "correct_action": 3,  # Investigate
                "label": "unknown"
            })
        
        np.random.shuffle(scenarios)
        return scenarios
    
    def reset(self, seed=None):
        super().reset(seed=seed)
        self.current_step = 0
        self.total_reward = 0
        self.scenarios = self._generate_scenarios()
        return self.scenarios[0]["features"], {}
    
    def step(self, action):
        scenario = self.scenarios[self.current_step % len(self.scenarios)]
        correct_action = scenario["correct_action"]
        
        # Reward system
        if action == correct_action:
            reward = 10  # Bilkul sahi decision!
        elif action == 1 and correct_action == 2:
            reward = 3   # Block kiya jab alert karna tha — thoda sahi
        elif action == 2 and correct_action == 1:
            reward = 2   # Alert kiya jab block karna tha — thoda sahi
        elif action == 0 and correct_action != 0:
            reward = -10  # Attack allow kar diya — bahut galat!
        else:
            reward = -5   # Galat decision
        
        self.total_reward += reward
        self.current_step += 1
        
        done = self.current_step >= self.max_steps
        next_state = self.scenarios[self.current_step % len(self.scenarios)]["features"]
        
        return next_state, reward, done, False, {
            "action_taken": self.action_names[action],
            "correct_action": self.action_names[correct_action],
            "label": scenario["label"]
        }

# ============================================
# 2. ENVIRONMENT TEST
# ============================================
print("Environment check kar raha hoon...")
env = NetworkSecurityEnv()
check_env(env)
print("Environment OK!")

# ============================================
# 3. PPO AGENT TRAIN KARO
# ============================================
print("\nPPO Agent train ho raha hai...")
print("AI khud seekh raha hai — trial and error se!")

model = PPO(
    "MlpPolicy",
    env,
    verbose=1,
    learning_rate=0.0003,
    n_steps=2048,
    batch_size=64,
    n_epochs=10,
    gamma=0.99,
    tensorboard_log="./rl_logs/"
)

model.learn(total_timesteps=50000)

# ============================================
# 4. EVALUATE
# ============================================
print("\nAgent evaluate kar raha hoon...")
obs, _ = env.reset()
total_reward = 0
correct = 0
total = 100

for i in range(total):
    action, _ = model.predict(obs, deterministic=True)
    obs, reward, done, _, info = env.step(action)
    total_reward += reward
    if reward == 10:
        correct += 1
    if done:
        obs, _ = env.reset()

accuracy = (correct / total) * 100
print(f"\n{'='*60}")
print(f"RL Agent Accuracy: {accuracy:.1f}%")
print(f"Total Reward: {total_reward}")
print(f"Correct Decisions: {correct}/{total}")
print(f"{'='*60}")

# ============================================
# 5. MODEL SAVE
# ============================================
model.save("rl_ids_agent")
print("\nRL Agent saved — rl_ids_agent.zip")

print("\nRL Training Complete!")
print("AI ab khud decisions leta hai — block, allow, alert, investigate!")