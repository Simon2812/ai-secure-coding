from model import SecureCodingModel


model = SecureCodingModel()

model.load_model()

model.save_checkpoint(
    "./checkpoints/test"
)

model.load_checkpoint(
    "./checkpoints/test"
)

print("Task 2 works.")
